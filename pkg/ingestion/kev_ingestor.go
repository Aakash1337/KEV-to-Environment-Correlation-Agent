package ingestion

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/Aakash1337/KEV-to-Environment-Correlation-Agent/internal/models"
	"github.com/Aakash1337/KEV-to-Environment-Correlation-Agent/pkg/config"
	"gorm.io/gorm"
)

// KEVCatalog represents the CISA KEV catalog structure
type KEVCatalog struct {
	Title            string         `json:"title"`
	CatalogVersion   string         `json:"catalogVersion"`
	DateReleased     string         `json:"dateReleased"`
	Count            int            `json:"count"`
	Vulnerabilities  []KEVVulnerability `json:"vulnerabilities"`
}

// KEVVulnerability represents a single vulnerability in the KEV catalog
type KEVVulnerability struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
}

// KEVIngestor handles KEV catalog ingestion
type KEVIngestor struct {
	config *config.Config
	db     *gorm.DB
}

// NewKEVIngestor creates a new KEV ingestor
func NewKEVIngestor(cfg *config.Config, db *gorm.DB) *KEVIngestor {
	return &KEVIngestor{
		config: cfg,
		db:     db,
	}
}

// Sync syncs the KEV catalog from CISA
func (k *KEVIngestor) Sync() (*SyncResult, error) {
	log.Println("Starting KEV sync...")

	// Download KEV catalog
	catalog, rawData, err := k.downloadKEV()
	if err != nil {
		return nil, fmt.Errorf("failed to download KEV: %w", err)
	}

	// Calculate snapshot ID (hash of raw data)
	hash := sha256.Sum256(rawData)
	snapshotID := hex.EncodeToString(hash[:])

	// Check if we've already processed this snapshot
	var existingSnapshot models.KEVSnapshot
	if err := k.db.Where("snapshot_id = ?", snapshotID).First(&existingSnapshot).Error; err == nil {
		log.Printf("KEV catalog unchanged (snapshot: %s)", snapshotID)
		return &SyncResult{
			SnapshotID:      snapshotID,
			TotalEntries:    catalog.Count,
			NewEntries:      0,
			UpdatedEntries:  0,
			RemovedEntries:  0,
			AlreadyUpToDate: true,
		}, nil
	}

	// Process vulnerabilities
	newCount := 0
	updatedCount := 0

	for _, vuln := range catalog.Vulnerabilities {
		entry := k.convertToKEVEntry(vuln, snapshotID)

		var existing models.KEVEntry
		result := k.db.Where("cve_id = ?", vuln.CVEID).First(&existing)

		if result.Error == gorm.ErrRecordNotFound {
			// New entry
			if err := k.db.Create(&entry).Error; err != nil {
				log.Printf("Error creating KEV entry %s: %v", vuln.CVEID, err)
				continue
			}
			newCount++
		} else {
			// Update existing
			entry.ID = existing.ID
			entry.FirstSeen = existing.FirstSeen
			if err := k.db.Save(&entry).Error; err != nil {
				log.Printf("Error updating KEV entry %s: %v", vuln.CVEID, err)
				continue
			}
			updatedCount++
		}
	}

	// Create snapshot record
	var rawDataJSON models.JSONB
	_ = json.Unmarshal(rawData, &rawDataJSON)

	catalogDate, _ := time.Parse("2006-01-02", catalog.DateReleased)
	snapshot := models.KEVSnapshot{
		SnapshotID:          snapshotID,
		CatalogVersion:      catalog.CatalogVersion,
		CatalogDate:         &catalogDate,
		EntryCount:          catalog.Count,
		NewEntriesCount:     newCount,
		UpdatedEntriesCount: updatedCount,
		RemovedEntriesCount: 0,
		RawData:             rawDataJSON,
	}

	if err := k.db.Create(&snapshot).Error; err != nil {
		log.Printf("Error creating snapshot: %v", err)
	}

	// Create audit log
	audit := models.AuditLog{
		Timestamp: time.Now(),
		Operation: "kev_sync",
		Details: models.JSONB{
			"snapshot_id":      snapshotID,
			"total_entries":    catalog.Count,
			"new_entries":      newCount,
			"updated_entries":  updatedCount,
			"catalog_version":  catalog.CatalogVersion,
		},
		Result: "success",
	}
	k.db.Create(&audit)

	log.Printf("KEV sync completed: %d total, %d new, %d updated", catalog.Count, newCount, updatedCount)

	return &SyncResult{
		SnapshotID:      snapshotID,
		TotalEntries:    catalog.Count,
		NewEntries:      newCount,
		UpdatedEntries:  updatedCount,
		RemovedEntries:  0,
		AlreadyUpToDate: false,
	}, nil
}

// downloadKEV downloads the KEV catalog
func (k *KEVIngestor) downloadKEV() (*KEVCatalog, []byte, error) {
	url := k.config.KEV.SourceURL

	resp, err := http.Get(url)
	if err != nil {
		// Try GitHub mirror as fallback
		log.Printf("Primary source failed, trying GitHub mirror...")
		url = k.config.KEV.GitHubMirror
		resp, err = http.Get(url)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to download from both sources: %w", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response: %w", err)
	}

	var catalog KEVCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, nil, fmt.Errorf("failed to parse KEV catalog: %w", err)
	}

	return &catalog, body, nil
}

// convertToKEVEntry converts a KEV vulnerability to database model
func (k *KEVIngestor) convertToKEVEntry(vuln KEVVulnerability, snapshotID string) models.KEVEntry {
	now := time.Now()

	var dateAdded *time.Time
	if vuln.DateAdded != "" {
		if t, err := time.Parse("2006-01-02", vuln.DateAdded); err == nil {
			dateAdded = &t
		}
	}

	var dueDate *time.Time
	if vuln.DueDate != "" {
		if t, err := time.Parse("2006-01-02", vuln.DueDate); err == nil {
			dueDate = &t
		}
	}

	return models.KEVEntry{
		CVEID:                      vuln.CVEID,
		VendorProject:              vuln.VendorProject,
		Product:                    vuln.Product,
		VulnerabilityName:          vuln.VulnerabilityName,
		DateAdded:                  dateAdded,
		ShortDescription:           vuln.ShortDescription,
		RequiredAction:             vuln.RequiredAction,
		DueDate:                    dueDate,
		KnownRansomwareCampaignUse: vuln.KnownRansomwareCampaignUse,
		Notes:                      vuln.Notes,
		References:                 models.StringArray{},
		FirstSeen:                  now,
		LastUpdated:                now,
		SnapshotID:                 snapshotID,
	}
}

// SyncResult contains the results of a KEV sync operation
type SyncResult struct {
	SnapshotID      string
	TotalEntries    int
	NewEntries      int
	UpdatedEntries  int
	RemovedEntries  int
	AlreadyUpToDate bool
}
