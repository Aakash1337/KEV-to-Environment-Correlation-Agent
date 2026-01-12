package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Path string `mapstructure:"path"`
}

// KEVConfig holds KEV source configuration
type KEVConfig struct {
	SourceURL          string `mapstructure:"source_url"`
	GitHubMirror       string `mapstructure:"github_mirror"`
	SyncIntervalHours  int    `mapstructure:"sync_interval_hours"`
}

// AIConfig holds AI assistant configuration
type AIConfig struct {
	Provider    string  `mapstructure:"provider"`
	Model       string  `mapstructure:"model"`
	MaxTokens   int     `mapstructure:"max_tokens"`
	Temperature float64 `mapstructure:"temperature"`
}

// PrioritizationWeights holds prioritization weight configuration
type PrioritizationWeights struct {
	AssetCriticality float64 `mapstructure:"asset_criticality"`
	Exposure         float64 `mapstructure:"exposure"`
	KEVAge           float64 `mapstructure:"kev_age"`
	FindingAge       float64 `mapstructure:"finding_age"`
}

// CriticalityScores holds asset criticality scores
type CriticalityScores struct {
	Critical int `mapstructure:"critical"`
	High     int `mapstructure:"high"`
	Medium   int `mapstructure:"medium"`
	Low      int `mapstructure:"low"`
}

// ExposureScores holds exposure level scores
type ExposureScores struct {
	InternetFacing int `mapstructure:"internet_facing"`
	VPNOnly        int `mapstructure:"vpn_only"`
	InternalOnly   int `mapstructure:"internal_only"`
}

// PrioritizationConfig holds prioritization configuration
type PrioritizationConfig struct {
	Weights           PrioritizationWeights `mapstructure:"weights"`
	CriticalityScores CriticalityScores     `mapstructure:"criticality_scores"`
	ExposureScores    ExposureScores        `mapstructure:"exposure_scores"`
}

// ReportingConfig holds reporting configuration
type ReportingConfig struct {
	DefaultExportPath string `mapstructure:"default_export_path"`
	IncludeEvidence   bool   `mapstructure:"include_evidence"`
	MaxItemsPerReport int    `mapstructure:"max_items_per_report"`
}

// AuditConfig holds audit configuration
type AuditConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	LogPath string `mapstructure:"log_path"`
}

// Config is the main configuration structure
type Config struct {
	Database       DatabaseConfig       `mapstructure:"database"`
	KEV            KEVConfig            `mapstructure:"kev"`
	AI             AIConfig             `mapstructure:"ai"`
	Prioritization PrioritizationConfig `mapstructure:"prioritization"`
	Reporting      ReportingConfig      `mapstructure:"reporting"`
	Audit          AuditConfig          `mapstructure:"audit"`

	// Environment variables
	AnthropicAPIKey string
}

// Load loads configuration from file and environment
func Load(configPath string) (*Config, error) {
	// Load .env file if it exists
	_ = godotenv.Load()

	// Set defaults
	viper.SetDefault("database.path", "data/kev_mapper.db")
	viper.SetDefault("kev.source_url", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	viper.SetDefault("kev.github_mirror", "https://raw.githubusercontent.com/cisagov/KEV/main/known_exploited_vulnerabilities.json")
	viper.SetDefault("kev.sync_interval_hours", 24)

	viper.SetDefault("ai.provider", "anthropic")
	viper.SetDefault("ai.model", "claude-sonnet-4-5-20250929")
	viper.SetDefault("ai.max_tokens", 4096)
	viper.SetDefault("ai.temperature", 0.3)

	viper.SetDefault("prioritization.weights.asset_criticality", 0.35)
	viper.SetDefault("prioritization.weights.exposure", 0.30)
	viper.SetDefault("prioritization.weights.kev_age", 0.20)
	viper.SetDefault("prioritization.weights.finding_age", 0.15)

	viper.SetDefault("prioritization.criticality_scores.critical", 10)
	viper.SetDefault("prioritization.criticality_scores.high", 7)
	viper.SetDefault("prioritization.criticality_scores.medium", 4)
	viper.SetDefault("prioritization.criticality_scores.low", 2)

	viper.SetDefault("prioritization.exposure_scores.internet_facing", 10)
	viper.SetDefault("prioritization.exposure_scores.vpn_only", 5)
	viper.SetDefault("prioritization.exposure_scores.internal_only", 2)

	viper.SetDefault("reporting.default_export_path", "exports/")
	viper.SetDefault("reporting.include_evidence", true)
	viper.SetDefault("reporting.max_items_per_report", 50)

	viper.SetDefault("audit.enabled", true)
	viper.SetDefault("audit.log_path", "data/audit.log")

	// Read config file if provided
	if configPath != "" {
		viper.SetConfigFile(configPath)
		if err := viper.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Load environment variables
	config.AnthropicAPIKey = os.Getenv("ANTHROPIC_API_KEY")

	return &config, nil
}
