"""
CSV export functionality
"""
import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from sqlalchemy.orm import Session

from ..database import Match, Asset, KEVEntry, MatchStatus

logger = logging.getLogger(__name__)


class CSVExporter:
    """Export matches to CSV format"""

    def __init__(self, db_session: Session, export_path: str = "exports/"):
        """
        Initialize CSV exporter

        Args:
            db_session: Database session
            export_path: Directory for exports
        """
        self.session = db_session
        self.export_path = Path(export_path)
        self.export_path.mkdir(parents=True, exist_ok=True)

    def export_matches(self, matches: List[Match], output_file: Optional[str] = None) -> str:
        """
        Export matches to CSV

        Args:
            matches: List of Match objects
            output_file: Optional output filename

        Returns:
            Path to exported file
        """
        if not output_file:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_file = f"matches_{timestamp}.csv"

        output_path = self.export_path / output_file

        # Define CSV columns
        fieldnames = [
            "match_id",
            "cve_id",
            "vulnerability_name",
            "product",
            "hostname",
            "ip_address",
            "asset_criticality",
            "asset_environment",
            "asset_exposure",
            "priority_score",
            "status",
            "confidence_level",
            "date_added_to_kev",
            "match_created_at",
            "match_rationale"
        ]

        with open(output_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for match in matches:
                kev_entry = self.session.query(KEVEntry).filter_by(id=match.kev_entry_id).first()
                asset = self.session.query(Asset).filter_by(id=match.asset_id).first()

                if not kev_entry or not asset:
                    continue

                row = {
                    "match_id": match.id,
                    "cve_id": kev_entry.cve_id,
                    "vulnerability_name": kev_entry.vulnerability_name or "",
                    "product": kev_entry.product or "",
                    "hostname": asset.hostname,
                    "ip_address": asset.ip_address or "",
                    "asset_criticality": asset.criticality.value if asset.criticality else "",
                    "asset_environment": asset.environment.value if asset.environment else "",
                    "asset_exposure": asset.exposure.value if asset.exposure else "",
                    "priority_score": f"{match.priority_score:.1f}" if match.priority_score else "",
                    "status": match.status.value if isinstance(match.status, MatchStatus) else match.status,
                    "confidence_level": match.confidence_level or "",
                    "date_added_to_kev": kev_entry.date_added.strftime("%Y-%m-%d") if kev_entry.date_added else "",
                    "match_created_at": match.created_at.strftime("%Y-%m-%d %H:%M:%S") if match.created_at else "",
                    "match_rationale": match.match_rationale or "",
                }

                writer.writerow(row)

        logger.info(f"Exported {len(matches)} matches to {output_path}")

        return str(output_path)

    def export_work_queue(self, limit: int = 100, output_file: Optional[str] = None) -> str:
        """
        Export prioritized work queue to CSV

        Args:
            limit: Maximum number of matches to export
            output_file: Optional output filename

        Returns:
            Path to exported file
        """
        if not output_file:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_file = f"work_queue_{timestamp}.csv"

        # Get open matches ordered by priority
        matches = self.session.query(Match).filter(
            Match.status == "open"
        ).order_by(Match.priority_score.desc()).limit(limit).all()

        return self.export_matches(matches, output_file)
