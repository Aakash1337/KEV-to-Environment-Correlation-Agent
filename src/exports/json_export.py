"""
JSON export functionality
"""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session

from ..database import Match, Asset, KEVEntry, Finding, MatchStatus

logger = logging.getLogger(__name__)


class JSONExporter:
    """Export matches and data to JSON format"""

    def __init__(self, db_session: Session, export_path: str = "exports/"):
        """
        Initialize JSON exporter

        Args:
            db_session: Database session
            export_path: Directory for exports
        """
        self.session = db_session
        self.export_path = Path(export_path)
        self.export_path.mkdir(parents=True, exist_ok=True)

    def _serialize_match(self, match: Match, include_evidence: bool = True) -> Dict[str, Any]:
        """
        Serialize a match to dictionary

        Args:
            match: Match object
            include_evidence: Include full evidence details

        Returns:
            Dictionary representation
        """
        kev_entry = self.session.query(KEVEntry).filter_by(id=match.kev_entry_id).first()
        asset = self.session.query(Asset).filter_by(id=match.asset_id).first()

        match_dict = {
            "match_id": match.id,
            "status": match.status.value if isinstance(match.status, MatchStatus) else match.status,
            "confidence_level": match.confidence_level,
            "priority_score": match.priority_score,
            "match_rationale": match.match_rationale,
            "created_at": match.created_at.isoformat() if match.created_at else None,
            "updated_at": match.updated_at.isoformat() if match.updated_at else None,
        }

        if kev_entry:
            match_dict["kev_entry"] = {
                "cve_id": kev_entry.cve_id,
                "vendor_project": kev_entry.vendor_project,
                "product": kev_entry.product,
                "vulnerability_name": kev_entry.vulnerability_name,
                "short_description": kev_entry.short_description,
                "required_action": kev_entry.required_action,
                "date_added": kev_entry.date_added.isoformat() if kev_entry.date_added else None,
                "due_date": kev_entry.due_date.isoformat() if kev_entry.due_date else None,
                "known_ransomware_campaign_use": kev_entry.known_ransomware_campaign_use,
            }

        if asset:
            match_dict["asset"] = {
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "operating_system": asset.operating_system,
                "criticality": asset.criticality.value if asset.criticality else None,
                "environment": asset.environment.value if asset.environment else None,
                "exposure": asset.exposure.value if asset.exposure else None,
                "owner": asset.owner,
                "tags": asset.tags,
            }

        if include_evidence and match.evidence_finding_ids:
            findings = []
            for finding_id in match.evidence_finding_ids:
                finding = self.session.query(Finding).filter_by(id=finding_id).first()
                if finding:
                    findings.append({
                        "finding_id": finding.id,
                        "source": finding.source,
                        "product": finding.product,
                        "detected_version": finding.detected_version,
                        "severity": finding.severity,
                        "detected_at": finding.detected_at.isoformat() if finding.detected_at else None,
                        "evidence": finding.evidence_blob,
                    })
            match_dict["evidence"] = findings

        if match.remediation_packet:
            match_dict["remediation_packet"] = match.remediation_packet

        if match.priority_factors:
            match_dict["priority_factors"] = match.priority_factors

        return match_dict

    def export_match(self, match: Match, output_file: Optional[str] = None) -> str:
        """
        Export a single match to JSON

        Args:
            match: Match object
            output_file: Optional output filename

        Returns:
            Path to exported file
        """
        kev_entry = self.session.query(KEVEntry).filter_by(id=match.kev_entry_id).first()
        asset = self.session.query(Asset).filter_by(id=match.asset_id).first()

        if not output_file:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            cve_id = kev_entry.cve_id if kev_entry else "unknown"
            hostname = asset.hostname if asset else "unknown"
            output_file = f"match_{cve_id}_{hostname}_{timestamp}.json"

        output_path = self.export_path / output_file

        match_data = self._serialize_match(match, include_evidence=True)

        with open(output_path, 'w') as f:
            json.dump(match_data, f, indent=2)

        logger.info(f"Exported match {match.id} to {output_path}")

        return str(output_path)

    def export_multiple_matches(self, matches: List[Match], output_file: Optional[str] = None) -> str:
        """
        Export multiple matches to JSON

        Args:
            matches: List of Match objects
            output_file: Optional output filename

        Returns:
            Path to exported file
        """
        if not output_file:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_file = f"matches_{timestamp}.json"

        output_path = self.export_path / output_file

        matches_data = {
            "generated_at": datetime.utcnow().isoformat(),
            "total_matches": len(matches),
            "matches": [self._serialize_match(match) for match in matches]
        }

        with open(output_path, 'w') as f:
            json.dump(matches_data, f, indent=2)

        logger.info(f"Exported {len(matches)} matches to {output_path}")

        return str(output_path)

    def export_work_queue(self, limit: int = 50, output_file: Optional[str] = None) -> str:
        """
        Export prioritized work queue to JSON

        Args:
            limit: Maximum number of matches to export
            output_file: Optional output filename

        Returns:
            Path to exported file
        """
        if not output_file:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_file = f"work_queue_{timestamp}.json"

        output_path = self.export_path / output_file

        # Get open matches ordered by priority
        matches = self.session.query(Match).filter(
            Match.status == "open"
        ).order_by(Match.priority_score.desc()).limit(limit).all()

        queue_data = {
            "generated_at": datetime.utcnow().isoformat(),
            "total_items": len(matches),
            "queue": [self._serialize_match(match) for match in matches]
        }

        with open(output_path, 'w') as f:
            json.dump(queue_data, f, indent=2)

        logger.info(f"Exported work queue with {len(matches)} items to {output_path}")

        return str(output_path)
