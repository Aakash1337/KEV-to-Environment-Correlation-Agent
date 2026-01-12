package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

// JSONB is a custom type for storing JSON in the database
type JSONB map[string]interface{}

// Scan implements the sql.Scanner interface
func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = make(JSONB)
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, j)
}

// Value implements the driver.Valuer interface
func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// StringArray is a custom type for string arrays
type StringArray []string

// Scan implements the sql.Scanner interface
func (s *StringArray) Scan(value interface{}) error {
	if value == nil {
		*s = []string{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, s)
}

// Value implements the driver.Valuer interface
func (s StringArray) Value() (driver.Value, error){
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}

// IntArray is a custom type for integer arrays
type IntArray []int

// Scan implements the sql.Scanner interface
func (i *IntArray) Scan(value interface{}) error {
	if value == nil {
		*i = []int{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, i)
}

// Value implements the driver.Valuer interface
func (i IntArray) Value() (driver.Value, error) {
	if i == nil {
		return nil, nil
	}
	return json.Marshal(i)
}

// MatchStatus represents the status of a KEV-to-asset match
type MatchStatus string

const (
	MatchStatusOpen          MatchStatus = "open"
	MatchStatusMitigated     MatchStatus = "mitigated"
	MatchStatusFalsePositive MatchStatus = "false_positive"
	MatchStatusInProgress    MatchStatus = "in_progress"
)

// AssetCriticality represents asset criticality levels
type AssetCriticality string

const (
	CriticalityCritical AssetCriticality = "critical"
	CriticalityHigh     AssetCriticality = "high"
	CriticalityMedium   AssetCriticality = "medium"
	CriticalityLow      AssetCriticality = "low"
)

// AssetEnvironment represents asset environment types
type AssetEnvironment string

const (
	EnvironmentProduction  AssetEnvironment = "production"
	EnvironmentDevelopment AssetEnvironment = "development"
	EnvironmentStaging     AssetEnvironment = "staging"
	EnvironmentTest        AssetEnvironment = "test"
)

// ExposureLevel represents asset exposure levels
type ExposureLevel string

const (
	ExposureInternetFacing ExposureLevel = "internet_facing"
	ExposureVPNOnly        ExposureLevel = "vpn_only"
	ExposureInternalOnly   ExposureLevel = "internal_only"
)

// KEVEntry represents a Known Exploited Vulnerability entry from CISA
type KEVEntry struct {
	gorm.Model
	CVEID                        string     `gorm:"uniqueIndex;size:20;not null" json:"cve_id"`
	VendorProject                string     `gorm:"size:255" json:"vendor_project"`
	Product                      string     `gorm:"size:255" json:"product"`
	VulnerabilityName            string     `gorm:"size:500" json:"vulnerability_name"`
	DateAdded                    *time.Time `json:"date_added"`
	ShortDescription             string     `gorm:"type:text" json:"short_description"`
	RequiredAction               string     `gorm:"type:text" json:"required_action"`
	DueDate                      *time.Time `json:"due_date"`
	KnownRansomwareCampaignUse   string     `gorm:"size:50" json:"known_ransomware_campaign_use"`
	Notes                        string     `gorm:"type:text" json:"notes"`
	References                   StringArray `gorm:"type:json" json:"references"`
	FirstSeen                    time.Time  `json:"first_seen"`
	LastUpdated                  time.Time  `json:"last_updated"`
	SnapshotID                   string     `gorm:"size:64;index" json:"snapshot_id"`
	Matches                      []Match    `gorm:"foreignKey:KEVEntryID;constraint:OnDelete:CASCADE" json:"-"`
}

// Asset represents an asset in the environment
type Asset struct {
	gorm.Model
	Hostname             string           `gorm:"not null" json:"hostname"`
	IPAddress            string           `gorm:"size:45" json:"ip_address"`
	OperatingSystem      string           `gorm:"size:255" json:"operating_system"`
	OSVersion            string           `gorm:"size:100" json:"os_version"`
	Owner                string           `gorm:"size:255" json:"owner"`
	Tags                 StringArray      `gorm:"type:json" json:"tags"`
	Criticality          AssetCriticality `gorm:"type:varchar(20);default:'medium'" json:"criticality"`
	Environment          AssetEnvironment `gorm:"type:varchar(20);default:'production'" json:"environment"`
	Exposure             ExposureLevel    `gorm:"type:varchar(20);default:'internal_only'" json:"exposure"`
	Description          string           `gorm:"type:text" json:"description"`
	Location             string           `gorm:"size:255" json:"location"`
	CompensatingControls StringArray      `gorm:"type:json" json:"compensating_controls"`
	LastScanned          *time.Time       `json:"last_scanned"`
	Findings             []Finding        `gorm:"foreignKey:AssetID;constraint:OnDelete:CASCADE" json:"-"`
	Matches              []Match          `gorm:"foreignKey:AssetID;constraint:OnDelete:CASCADE" json:"-"`
}

// Finding represents a vulnerability finding from scanner or inventory
type Finding struct {
	gorm.Model
	AssetID         uint      `gorm:"not null;index" json:"asset_id"`
	CVEID           string    `gorm:"size:20;index" json:"cve_id"`
	Product         string    `gorm:"size:255" json:"product"`
	DetectedVersion string    `gorm:"size:100" json:"detected_version"`
	EvidenceBlob    JSONB     `gorm:"type:json" json:"evidence_blob"`
	Source          string    `gorm:"size:100" json:"source"`
	SourceID        string    `gorm:"size:255" json:"source_id"`
	Severity        string    `gorm:"size:20" json:"severity"`
	CPE             string    `gorm:"size:500" json:"cpe"`
	DetectedAt      time.Time `json:"detected_at"`
	ImportedAt      time.Time `json:"imported_at"`
	Asset           Asset     `gorm:"foreignKey:AssetID" json:"-"`
}

// Match represents a correlation between KEV entry and asset
type Match struct {
	gorm.Model
	KEVEntryID             uint         `gorm:"not null;index" json:"kev_entry_id"`
	AssetID                uint         `gorm:"not null;index" json:"asset_id"`
	ConfidenceLevel        string       `gorm:"size:50" json:"confidence_level"`
	EvidenceFindingIDs     IntArray     `gorm:"type:json" json:"evidence_finding_ids"`
	MatchRationale         string       `gorm:"type:text" json:"match_rationale"`
	Status                 MatchStatus  `gorm:"type:varchar(20);default:'open';index" json:"status"`
	FalsePositiveReason    string       `gorm:"type:text" json:"false_positive_reason"`
	PriorityScore          float64      `json:"priority_score"`
	PriorityFactors        JSONB        `gorm:"type:json" json:"priority_factors"`
	RemediationPacket      JSONB        `gorm:"type:json" json:"remediation_packet"`
	RemediationGeneratedAt *time.Time   `json:"remediation_generated_at"`
	MitigatedAt            *time.Time   `json:"mitigated_at"`
	MitigationNotes        string       `gorm:"type:text" json:"mitigation_notes"`
	KEVEntry               KEVEntry     `gorm:"foreignKey:KEVEntryID" json:"-"`
	Asset                  Asset        `gorm:"foreignKey:AssetID" json:"-"`
}

// AuditLog represents an audit trail for all operations
type AuditLog struct {
	gorm.Model
	Timestamp    time.Time `gorm:"index" json:"timestamp"`
	Operation    string    `gorm:"size:100;index" json:"operation"`
	Details      JSONB     `gorm:"type:json" json:"details"`
	User         string    `gorm:"size:100" json:"user"`
	Result       string    `gorm:"size:20" json:"result"`
	ErrorMessage string    `gorm:"type:text" json:"error_message"`
}

// KEVSnapshot represents historical snapshots of KEV catalog
type KEVSnapshot struct {
	gorm.Model
	SnapshotID           string    `gorm:"uniqueIndex;size:64;not null" json:"snapshot_id"`
	CatalogVersion       string    `gorm:"size:50" json:"catalog_version"`
	CatalogDate          *time.Time `json:"catalog_date"`
	EntryCount           int       `json:"entry_count"`
	NewEntriesCount      int       `json:"new_entries_count"`
	UpdatedEntriesCount  int       `json:"updated_entries_count"`
	RemovedEntriesCount  int       `json:"removed_entries_count"`
	RawData              JSONB     `gorm:"type:json" json:"raw_data"`
}
