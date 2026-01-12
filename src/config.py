"""
Configuration management for KEV Mapper
"""
import yaml
from pathlib import Path
from typing import Dict, Any
import os
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class DatabaseConfig(BaseModel):
    """Database configuration"""
    path: str = "data/kev_mapper.db"


class KEVConfig(BaseModel):
    """KEV source configuration"""
    source_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    github_mirror: str = "https://raw.githubusercontent.com/cisagov/KEV/main/known_exploited_vulnerabilities.json"
    sync_interval_hours: int = 24


class AIConfig(BaseModel):
    """AI assistant configuration"""
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-5-20250929"
    max_tokens: int = 4096
    temperature: float = 0.3


class PrioritizationWeights(BaseModel):
    """Prioritization weight configuration"""
    asset_criticality: float = 0.35
    exposure: float = 0.30
    kev_age: float = 0.20
    finding_age: float = 0.15


class CriticalityScores(BaseModel):
    """Asset criticality scores"""
    critical: int = 10
    high: int = 7
    medium: int = 4
    low: int = 2


class ExposureScores(BaseModel):
    """Exposure level scores"""
    internet_facing: int = 10
    vpn_only: int = 5
    internal_only: int = 2


class PrioritizationConfig(BaseModel):
    """Prioritization configuration"""
    weights: PrioritizationWeights = Field(default_factory=PrioritizationWeights)
    criticality_scores: CriticalityScores = Field(default_factory=CriticalityScores)
    exposure_scores: ExposureScores = Field(default_factory=ExposureScores)


class ReportingConfig(BaseModel):
    """Reporting configuration"""
    default_export_path: str = "exports/"
    include_evidence: bool = True
    max_items_per_report: int = 50


class AuditConfig(BaseModel):
    """Audit configuration"""
    enabled: bool = True
    log_path: str = "data/audit.log"


class Config(BaseSettings):
    """Main configuration class"""
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    kev: KEVConfig = Field(default_factory=KEVConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    prioritization: PrioritizationConfig = Field(default_factory=PrioritizationConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)

    # API keys from environment
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


def load_config(config_path: str = "config.yaml") -> Config:
    """
    Load configuration from YAML file and environment variables

    Args:
        config_path: Path to config YAML file

    Returns:
        Config object
    """
    config_dict = {}

    # Load from YAML if exists
    if Path(config_path).exists():
        with open(config_path, "r") as f:
            config_dict = yaml.safe_load(f) or {}

    # Create config object (will also load from environment)
    config = Config(**config_dict)

    return config


# Global config instance
_config_instance = None


def get_config(config_path: str = "config.yaml") -> Config:
    """
    Get or create global config instance

    Args:
        config_path: Path to config file

    Returns:
        Config instance
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = load_config(config_path)
    return _config_instance
