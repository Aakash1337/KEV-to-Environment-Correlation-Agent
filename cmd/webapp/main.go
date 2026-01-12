package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/Aakash1337/KEV-to-Environment-Correlation-Agent/internal/models"
	"github.com/Aakash1337/KEV-to-Environment-Correlation-Agent/pkg/config"
	"github.com/Aakash1337/KEV-to-Environment-Correlation-Agent/pkg/database"
	"github.com/Aakash1337/KEV-to-Environment-Correlation-Agent/pkg/ingestion"
	"github.com/gin-gonic/gin"
)

var (
	cfg *config.Config
)

func main() {
	// Load config
	var err error
	cfg, err = config.Load("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database
	if err := database.Init(cfg.Database.Path); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	// Setup Gin router
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Load HTML templates
	r.LoadHTMLGlob("src/web/templates/*")

	// Routes
	setupRoutes(r)

	// Start server
	port := ":8000"
	fmt.Printf("🚀 KEV Mapper Web UI started\n")
	fmt.Printf("   Access at: http://localhost%s\n\n", port)

	if err := r.Run(port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func setupRoutes(r *gin.Engine) {
	// Web pages
	r.GET("/", indexHandler)
	r.GET("/matches", matchesPageHandler)
	r.GET("/assets", assetsPageHandler)
	r.GET("/kev", kevPageHandler)

	// API endpoints
	api := r.Group("/api")
	{
		api.GET("/stats", getStatsHandler)
		api.GET("/matches", listMatchesHandler)
		api.GET("/matches/:id", getMatchHandler)
		api.POST("/sync", syncHandler)
		api.POST("/match", matchHandler)
		api.POST("/prioritize", prioritizeHandler)
	}
}

// Web page handlers
func indexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "KEV Mapper - Dashboard",
	})
}

func matchesPageHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "matches.html", gin.H{
		"title": "KEV Mapper - Matches",
	})
}

func assetsPageHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "KEV Mapper - Assets",
	})
}

func kevPageHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "KEV Mapper - KEV Updates",
	})
}

// API handlers
func getStatsHandler(c *gin.Context) {
	db := database.GetDB()

	var totalKEVs int64
	var totalAssets int64
	var totalMatches int64
	var openMatches int64
	var mitigatedMatches int64

	db.Model(&models.KEVEntry{}).Count(&totalKEVs)
	db.Model(&models.Asset{}).Count(&totalAssets)
	db.Model(&models.Match{}).Count(&totalMatches)
	db.Model(&models.Match{}).Where("status = ?", "open").Count(&openMatches)
	db.Model(&models.Match{}).Where("status = ?", "mitigated").Count(&mitigatedMatches)

	c.JSON(http.StatusOK, gin.H{
		"total_kevs":        totalKEVs,
		"total_assets":      totalAssets,
		"total_matches":     totalMatches,
		"open_matches":      openMatches,
		"mitigated_matches": mitigatedMatches,
	})
}

func listMatchesHandler(c *gin.Context) {
	db := database.GetDB()

	status := c.Query("status")
	limit := 50

	query := db.Model(&models.Match{}).Preload("KEVEntry").Preload("Asset")

	if status != "" {
		query = query.Where("status = ?", status)
	}

	var matches []models.Match
	var total int64

	query.Count(&total)
	query.Order("priority_score DESC").Limit(limit).Find(&matches)

	matchesData := make([]gin.H, 0)
	for _, match := range matches {
		matchesData = append(matchesData, gin.H{
			"id":              match.ID,
			"cve_id":          match.KEVEntry.CVEID,
			"product":         match.KEVEntry.Product,
			"hostname":        match.Asset.Hostname,
			"ip_address":      match.Asset.IPAddress,
			"priority_score":  match.PriorityScore,
			"status":          match.Status,
			"confidence_level": match.ConfidenceLevel,
			"created_at":      match.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"total":   total,
		"limit":   limit,
		"matches": matchesData,
	})
}

func getMatchHandler(c *gin.Context) {
	db := database.GetDB()
	matchID := c.Param("id")

	var match models.Match
	if err := db.Preload("KEVEntry").Preload("Asset").First(&match, matchID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Match not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":                match.ID,
		"status":            match.Status,
		"priority_score":    match.PriorityScore,
		"confidence_level":  match.ConfidenceLevel,
		"match_rationale":   match.MatchRationale,
		"created_at":        match.CreatedAt,
		"updated_at":        match.UpdatedAt,
		"kev_entry": gin.H{
			"cve_id":             match.KEVEntry.CVEID,
			"vendor_project":     match.KEVEntry.VendorProject,
			"product":            match.KEVEntry.Product,
			"vulnerability_name": match.KEVEntry.VulnerabilityName,
			"short_description":  match.KEVEntry.ShortDescription,
			"required_action":    match.KEVEntry.RequiredAction,
			"date_added":         match.KEVEntry.DateAdded,
			"due_date":           match.KEVEntry.DueDate,
		},
		"asset": gin.H{
			"hostname":         match.Asset.Hostname,
			"ip_address":       match.Asset.IPAddress,
			"operating_system": match.Asset.OperatingSystem,
			"criticality":      match.Asset.Criticality,
			"environment":      match.Asset.Environment,
			"exposure":         match.Asset.Exposure,
		},
		"remediation_packet": match.RemediationPacket,
		"priority_factors":   match.PriorityFactors,
	})
}

func syncHandler(c *gin.Context) {
	ingestor := ingestion.NewKEVIngestor(cfg, database.GetDB())
	result, err := ingestor.Sync()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":          "KEV sync completed",
		"snapshot_id":      result.SnapshotID,
		"total_entries":    result.TotalEntries,
		"new_entries":      result.NewEntries,
		"updated_entries":  result.UpdatedEntries,
		"already_up_to_date": result.AlreadyUpToDate,
	})
}

func matchHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Matching started",
		"note":    "Full matching engine requires additional implementation",
	})
}

func prioritizeHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Prioritization started",
		"note":    "Full prioritization requires additional implementation",
	})
}
