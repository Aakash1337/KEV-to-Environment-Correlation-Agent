"""
Database models for KEV Mapper
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, JSON,
    ForeignKey, Float, Boolean, Enum as SQLEnum
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum

Base = declarative_base()


class MatchStatus(enum.Enum):
    """Status of a KEV-to-asset match"""
    OPEN = "open"
    MITIGATED = "mitigated"
    FALSE_POSITIVE = "false_positive"
    IN_PROGRESS = "in_progress"


class AssetCriticality(enum.Enum):
    """Asset criticality levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssetEnvironment(enum.Enum):
    """Asset environment types"""
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    STAGING = "staging"
    TEST = "test"


class ExposureLevel(enum.Enum):
    """Asset exposure levels"""
    INTERNET_FACING = "internet_facing"
    VPN_ONLY = "vpn_only"
    INTERNAL_ONLY = "internal_only"


class KEVEntry(Base):
    """Known Exploited Vulnerability entry from CISA"""
    __tablename__ = "kev_entries"

    id = Column(Integer, primary_key=True)
    cve_id = Column(String(20), unique=True, nullable=False, index=True)
    vendor_project = Column(String(255))
    product = Column(String(255))
    vulnerability_name = Column(String(500))
    date_added = Column(DateTime)
    short_description = Column(Text)
    required_action = Column(Text)
    due_date = Column(DateTime, nullable=True)
    known_ransomware_campaign_use = Column(String(50))
    notes = Column(Text)
    references = Column(JSON)  # Array of URLs

    # Metadata
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    snapshot_id = Column(String(64))  # Hash of KEV file when this was ingested

    # Relationships
    matches = relationship("Match", back_populates="kev_entry", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<KEVEntry {self.cve_id}: {self.product}>"


class Asset(Base):
    """Asset in the environment"""
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)
    hostname = Column(String(255), nullable=False)
    ip_address = Column(String(45))  # IPv6 compatible
    operating_system = Column(String(255))
    os_version = Column(String(100))
    owner = Column(String(255))
    tags = Column(JSON)  # Array of tags
    criticality = Column(SQLEnum(AssetCriticality), default=AssetCriticality.MEDIUM)
    environment = Column(SQLEnum(AssetEnvironment), default=AssetEnvironment.PRODUCTION)
    exposure = Column(SQLEnum(ExposureLevel), default=ExposureLevel.INTERNAL_ONLY)

    # Additional metadata
    description = Column(Text)
    location = Column(String(255))
    compensating_controls = Column(JSON)  # Array of control descriptions

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_scanned = Column(DateTime)

    # Relationships
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")
    matches = relationship("Match", back_populates="asset", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Asset {self.hostname} ({self.ip_address})>"


class Finding(Base):
    """Vulnerability finding from scanner or inventory"""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    cve_id = Column(String(20), index=True)
    product = Column(String(255))
    detected_version = Column(String(100))
    evidence_blob = Column(JSON)  # Full scanner output or package info
    source = Column(String(100))  # e.g., "nessus", "qualys", "osquery", "sbom"
    source_id = Column(String(255))  # Plugin ID, check ID, etc.
    severity = Column(String(20))

    # CPE matching data
    cpe = Column(String(500))

    # Timestamps
    detected_at = Column(DateTime, default=datetime.utcnow)
    imported_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    asset = relationship("Asset", back_populates="findings")

    def __repr__(self):
        return f"<Finding {self.cve_id or 'N/A'} on {self.asset_id}>"


class Match(Base):
    """Correlation between KEV entry and asset"""
    __tablename__ = "matches"

    id = Column(Integer, primary_key=True)
    kev_entry_id = Column(Integer, ForeignKey("kev_entries.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    # Match details
    confidence_level = Column(String(50))  # "direct_cve", "version_match", "cpe_match"
    evidence_finding_ids = Column(JSON)  # Array of finding IDs that support this match
    match_rationale = Column(Text)  # Explanation of why this matched

    # Status
    status = Column(SQLEnum(MatchStatus), default=MatchStatus.OPEN, index=True)
    false_positive_reason = Column(Text)

    # Priority score
    priority_score = Column(Float)
    priority_factors = Column(JSON)  # Breakdown of scoring

    # Remediation
    remediation_packet = Column(JSON)  # AI-generated remediation details
    remediation_generated_at = Column(DateTime)

    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    mitigated_at = Column(DateTime)
    mitigation_notes = Column(Text)

    # Relationships
    kev_entry = relationship("KEVEntry", back_populates="matches")
    asset = relationship("Asset", back_populates="matches")

    def __repr__(self):
        return f"<Match KEV:{self.kev_entry_id} -> Asset:{self.asset_id} ({self.status.value})>"


class AuditLog(Base):
    """Audit trail for all operations"""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    operation = Column(String(100), index=True)  # "kev_sync", "import", "match", "status_change"
    details = Column(JSON)
    user = Column(String(100))  # For future multi-user support
    result = Column(String(20))  # "success", "failure", "partial"
    error_message = Column(Text)

    def __repr__(self):
        return f"<AuditLog {self.operation} at {self.timestamp}>"


class KEVSnapshot(Base):
    """Historical snapshots of KEV catalog"""
    __tablename__ = "kev_snapshots"

    id = Column(Integer, primary_key=True)
    snapshot_id = Column(String(64), unique=True, nullable=False, index=True)
    catalog_version = Column(String(50))
    catalog_date = Column(DateTime)
    entry_count = Column(Integer)
    new_entries_count = Column(Integer, default=0)
    updated_entries_count = Column(Integer, default=0)
    removed_entries_count = Column(Integer, default=0)
    raw_data = Column(JSON)  # Full KEV JSON for reproducibility

    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<KEVSnapshot {self.snapshot_id} ({self.entry_count} entries)>"
