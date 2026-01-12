"""
Markdown export functionality
"""
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from sqlalchemy.orm import Session

from ..database import Match, Asset, KEVEntry, Finding

logger = logging.getLogger(__name__)


class MarkdownExporter:
    """Export matches and remediation packets to Markdown format"""

    def __init__(self, db_session: Session, export_path: str = "exports/"):
        """
        Initialize Markdown exporter

        Args:
            db_session: Database session
            export_path: Directory for exports
        """
        self.session = db_session
        self.export_path = Path(export_path)
        self.export_path.mkdir(parents=True, exist_ok=True)

    def export_match(self, match: Match, output_file: Optional[str] = None) -> str:
        """
        Export a single match to Markdown

        Args:
            match: Match object
            output_file: Optional output filename

        Returns:
            Path to exported file
        """
        # Load related objects
        kev_entry = self.session.query(KEVEntry).filter_by(id=match.kev_entry_id).first()
        asset = self.session.query(Asset).filter_by(id=match.asset_id).first()

        if not kev_entry or not asset:
            raise ValueError("Match missing KEV entry or asset")

        # Generate filename if not provided
        if not output_file:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_file = f"remediation_{kev_entry.cve_id}_{asset.hostname}_{timestamp}.md"

        output_path = self.export_path / output_file

        # Build Markdown content
        content = self._build_match_markdown(match, kev_entry, asset)

        # Write to file
        with open(output_path, 'w') as f:
            f.write(content)

        logger.info(f"Exported match {match.id} to {output_path}")

        return str(output_path)

    def _build_match_markdown(self, match: Match, kev_entry: KEVEntry, asset: Asset) -> str:
        """
        Build Markdown content for a match

        Args:
            match: Match object
            kev_entry: KEV entry
            asset: Asset object

        Returns:
            Markdown string
        """
        lines = [
            f"# Remediation Packet: {kev_entry.cve_id}",
            "",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Priority Score:** {match.priority_score:.1f}/100",
            f"**Status:** {match.status.value}",
            "",
            "---",
            "",
            "## Vulnerability Details",
            "",
            f"- **CVE ID:** {kev_entry.cve_id}",
            f"- **Vendor/Product:** {kev_entry.vendor_project} - {kev_entry.product}",
            f"- **Vulnerability Name:** {kev_entry.vulnerability_name}",
            f"- **Date Added to KEV:** {kev_entry.date_added}",
        ]

        if kev_entry.due_date:
            lines.append(f"- **Due Date:** {kev_entry.due_date}")

        lines.extend([
            f"- **Ransomware Campaign Use:** {kev_entry.known_ransomware_campaign_use}",
            "",
            "### Description",
            "",
            kev_entry.short_description or "N/A",
            "",
            "### Required Action",
            "",
            kev_entry.required_action or "N/A",
            "",
            "---",
            "",
            "## Affected Asset",
            "",
            f"- **Hostname:** {asset.hostname}",
            f"- **IP Address:** {asset.ip_address or 'N/A'}",
            f"- **Operating System:** {asset.operating_system or 'Unknown'}",
            f"- **Criticality:** {asset.criticality.value if asset.criticality else 'N/A'}",
            f"- **Environment:** {asset.environment.value if asset.environment else 'N/A'}",
            f"- **Exposure:** {asset.exposure.value if asset.exposure else 'N/A'}",
            "",
            "---",
            "",
            "## Match Evidence",
            "",
            f"- **Confidence Level:** {match.confidence_level}",
            f"- **Match Rationale:** {match.match_rationale}",
            "",
        ])

        # Add findings evidence
        if match.evidence_finding_ids:
            lines.append("### Supporting Findings")
            lines.append("")

            for finding_id in match.evidence_finding_ids:
                finding = self.session.query(Finding).filter_by(id=finding_id).first()
                if finding:
                    lines.extend([
                        f"#### Finding {finding_id}",
                        "",
                        f"- **Source:** {finding.source}",
                        f"- **Product:** {finding.product}",
                        f"- **Detected Version:** {finding.detected_version or 'N/A'}",
                        f"- **Severity:** {finding.severity or 'N/A'}",
                        f"- **Detected At:** {finding.detected_at}",
                        "",
                    ])

        lines.extend([
            "---",
            "",
        ])

        # Add remediation packet if available
        if match.remediation_packet:
            lines.extend(self._format_remediation_packet(match.remediation_packet))

        return "\n".join(lines)

    def _format_remediation_packet(self, packet: dict) -> List[str]:
        """
        Format remediation packet as Markdown

        Args:
            packet: Remediation packet dictionary

        Returns:
            List of Markdown lines
        """
        lines = [
            "## AI-Generated Remediation Guidance",
            "",
            "_Note: This guidance is AI-generated and should be reviewed by security personnel before implementation._",
            "",
        ]

        if "summary" in packet:
            lines.extend([
                "### Executive Summary",
                "",
                packet["summary"],
                "",
            ])

        if "remediation_steps" in packet:
            lines.extend([
                "### Remediation Steps",
                "",
            ])
            for i, step in enumerate(packet["remediation_steps"], 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        if "validation_commands" in packet:
            lines.extend([
                "### Validation Commands",
                "",
                "```bash",
            ])
            for cmd in packet["validation_commands"]:
                lines.append(cmd)
            lines.extend([
                "```",
                "",
            ])

        if "compensating_controls" in packet:
            lines.extend([
                "### Compensating Controls",
                "",
            ])
            for control in packet["compensating_controls"]:
                lines.append(f"- {control}")
            lines.append("")

        if "rollback_guidance" in packet:
            lines.extend([
                "### Rollback Guidance",
                "",
                packet["rollback_guidance"],
                "",
            ])

        if "monitoring_recommendations" in packet:
            lines.extend([
                "### Monitoring Recommendations",
                "",
                packet["monitoring_recommendations"],
                "",
            ])

        if "full_response" in packet:
            lines.extend([
                "### Full AI Response",
                "",
                packet["full_response"],
                "",
            ])

        return lines

    def export_multiple_matches(self, matches: List[Match], output_file: Optional[str] = None) -> str:
        """
        Export multiple matches to a single Markdown file

        Args:
            matches: List of Match objects
            output_file: Optional output filename

        Returns:
            Path to exported file
        """
        if not output_file:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_file = f"remediation_report_{timestamp}.md"

        output_path = self.export_path / output_file

        lines = [
            "# KEV Remediation Report",
            "",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Total Matches:** {len(matches)}",
            "",
            "---",
            "",
        ]

        for i, match in enumerate(matches, 1):
            kev_entry = self.session.query(KEVEntry).filter_by(id=match.kev_entry_id).first()
            asset = self.session.query(Asset).filter_by(id=match.asset_id).first()

            if not kev_entry or not asset:
                continue

            lines.extend([
                f"## Match {i}: {kev_entry.cve_id} on {asset.hostname}",
                "",
            ])

            lines.extend(self._build_match_markdown(match, kev_entry, asset).split("\n")[4:])  # Skip title
            lines.extend([
                "",
                "---",
                "",
            ])

        with open(output_path, 'w') as f:
            f.write("\n".join(lines))

        logger.info(f"Exported {len(matches)} matches to {output_path}")

        return str(output_path)

    def export_summary_report(self) -> str:
        """
        Export summary report of all open matches

        Returns:
            Path to exported file
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_file = f"kev_summary_{timestamp}.md"
        output_path = self.export_path / output_file

        # Get statistics
        total_matches = self.session.query(Match).count()
        open_matches = self.session.query(Match).filter(Match.status == "open").count()
        mitigated_matches = self.session.query(Match).filter(Match.status == "mitigated").count()

        # Get top priority matches
        top_matches = self.session.query(Match).filter(
            Match.status == "open"
        ).order_by(Match.priority_score.desc()).limit(10).all()

        lines = [
            "# KEV Mapper Summary Report",
            "",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "## Overview",
            "",
            f"- **Total Matches:** {total_matches}",
            f"- **Open:** {open_matches}",
            f"- **Mitigated:** {mitigated_matches}",
            "",
            "## Top Priority Items",
            "",
        ]

        for i, match in enumerate(top_matches, 1):
            kev_entry = self.session.query(KEVEntry).filter_by(id=match.kev_entry_id).first()
            asset = self.session.query(Asset).filter_by(id=match.asset_id).first()

            if kev_entry and asset:
                lines.extend([
                    f"### {i}. {kev_entry.cve_id} - {asset.hostname}",
                    "",
                    f"- **Priority Score:** {match.priority_score:.1f}/100",
                    f"- **Asset Criticality:** {asset.criticality.value if asset.criticality else 'N/A'}",
                    f"- **Exposure:** {asset.exposure.value if asset.exposure else 'N/A'}",
                    f"- **Product:** {kev_entry.product}",
                    "",
                ])

        with open(output_path, 'w') as f:
            f.write("\n".join(lines))

        logger.info(f"Exported summary report to {output_path}")

        return str(output_path)
