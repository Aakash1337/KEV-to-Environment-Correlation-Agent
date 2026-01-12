"""
Deterministic matching engine for KEV-to-Environment correlation
"""
import logging
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import and_

from ..database import KEVEntry, Asset, Finding, Match, MatchStatus, AuditLog
from ..config import Config

logger = logging.getLogger(__name__)


class MatchingEngine:
    """
    Deterministic matching engine that correlates KEV entries with environment assets
    """

    def __init__(self, config: Config, db_session: Session):
        """
        Initialize matching engine

        Args:
            config: Application configuration
            db_session: Database session
        """
        self.config = config
        self.session = db_session

    def run_matching(self, kev_cve_ids: Optional[List[str]] = None) -> Dict:
        """
        Run matching process for KEV entries against environment

        Args:
            kev_cve_ids: Optional list of specific CVE IDs to match (if None, match all)

        Returns:
            Dictionary with matching statistics
        """
        start_time = datetime.utcnow()
        logger.info("Starting KEV matching process")

        try:
            # Get KEV entries to process
            query = self.session.query(KEVEntry)
            if kev_cve_ids:
                query = query.filter(KEVEntry.cve_id.in_(kev_cve_ids))
            kev_entries = query.all()

            logger.info(f"Processing {len(kev_entries)} KEV entries")

            matches_created = 0
            matches_updated = 0

            for kev_entry in kev_entries:
                result = self._match_kev_entry(kev_entry)
                matches_created += result["created"]
                matches_updated += result["updated"]

            self.session.commit()

            # Log audit entry
            audit_log = AuditLog(
                operation="match",
                details={
                    "kev_entries_processed": len(kev_entries),
                    "matches_created": matches_created,
                    "matches_updated": matches_updated,
                    "duration_seconds": (datetime.utcnow() - start_time).total_seconds()
                },
                result="success"
            )
            self.session.add(audit_log)
            self.session.commit()

            logger.info(f"Matching completed: {matches_created} new, {matches_updated} updated")

            return {
                "status": "success",
                "kev_entries_processed": len(kev_entries),
                "matches_created": matches_created,
                "matches_updated": matches_updated
            }

        except Exception as e:
            self.session.rollback()
            logger.error(f"Matching failed: {e}", exc_info=True)

            # Log failure
            audit_log = AuditLog(
                operation="match",
                details={
                    "duration_seconds": (datetime.utcnow() - start_time).total_seconds()
                },
                result="failure",
                error_message=str(e)
            )
            self.session.add(audit_log)
            self.session.commit()

            raise

    def _match_kev_entry(self, kev_entry: KEVEntry) -> Dict:
        """
        Match a single KEV entry against all findings

        Args:
            kev_entry: KEV entry to match

        Returns:
            Dictionary with match statistics for this entry
        """
        matches_created = 0
        matches_updated = 0

        # Strategy 1: Direct CVE match (highest confidence)
        findings = self.session.query(Finding).filter(
            Finding.cve_id == kev_entry.cve_id
        ).all()

        for finding in findings:
            # Check if match already exists
            existing_match = self.session.query(Match).filter(
                and_(
                    Match.kev_entry_id == kev_entry.id,
                    Match.asset_id == finding.asset_id
                )
            ).first()

            if existing_match:
                # Update existing match
                self._update_match(existing_match, finding, "direct_cve")
                matches_updated += 1
            else:
                # Create new match
                self._create_match(kev_entry, finding, "direct_cve")
                matches_created += 1

        # Strategy 2: Product/version match (would require more sophisticated logic)
        # This could be expanded to check product names and versions against KEV details

        return {
            "created": matches_created,
            "updated": matches_updated
        }

    def _create_match(self, kev_entry: KEVEntry, finding: Finding, confidence_level: str) -> Match:
        """
        Create a new match record

        Args:
            kev_entry: KEV entry
            finding: Finding that triggered the match
            confidence_level: Confidence level of the match

        Returns:
            Created Match object
        """
        match_rationale = self._generate_match_rationale(kev_entry, finding, confidence_level)

        match = Match(
            kev_entry_id=kev_entry.id,
            asset_id=finding.asset_id,
            confidence_level=confidence_level,
            evidence_finding_ids=[finding.id],
            match_rationale=match_rationale,
            status=MatchStatus.OPEN,
            created_at=datetime.utcnow()
        )

        self.session.add(match)
        self.session.flush()  # Get the ID

        logger.debug(f"Created match: KEV {kev_entry.cve_id} -> Asset {finding.asset_id}")

        return match

    def _update_match(self, match: Match, finding: Finding, confidence_level: str):
        """
        Update an existing match record

        Args:
            match: Existing match
            finding: Finding that supports the match
            confidence_level: Updated confidence level
        """
        # Add finding to evidence if not already present
        evidence_ids = match.evidence_finding_ids or []
        if finding.id not in evidence_ids:
            evidence_ids.append(finding.id)
            match.evidence_finding_ids = evidence_ids

        # Update confidence if higher
        confidence_priority = {
            "direct_cve": 3,
            "version_match": 2,
            "cpe_match": 1
        }

        current_priority = confidence_priority.get(match.confidence_level, 0)
        new_priority = confidence_priority.get(confidence_level, 0)

        if new_priority > current_priority:
            match.confidence_level = confidence_level
            match.match_rationale = self._generate_match_rationale(
                match.kev_entry, finding, confidence_level
            )

        match.updated_at = datetime.utcnow()

        logger.debug(f"Updated match: {match.id}")

    def _generate_match_rationale(self, kev_entry: KEVEntry, finding: Finding, confidence_level: str) -> str:
        """
        Generate human-readable match rationale

        Args:
            kev_entry: KEV entry
            finding: Finding
            confidence_level: Confidence level

        Returns:
            Rationale string
        """
        if confidence_level == "direct_cve":
            return (
                f"Direct CVE match: {kev_entry.cve_id} found in {finding.source} scan. "
                f"Product: {finding.product or 'N/A'}, "
                f"Version: {finding.detected_version or 'N/A'}. "
                f"Source ID: {finding.source_id}"
            )
        elif confidence_level == "version_match":
            return (
                f"Product/version match: {kev_entry.product} matches finding. "
                f"Detected version: {finding.detected_version}"
            )
        elif confidence_level == "cpe_match":
            return (
                f"CPE match: {finding.cpe} matches KEV entry for {kev_entry.product}"
            )
        else:
            return "Match based on correlation rules"

    def get_matches_by_asset(self, asset_id: int, status: Optional[MatchStatus] = None) -> List[Match]:
        """
        Get all matches for a specific asset

        Args:
            asset_id: Asset ID
            status: Optional status filter

        Returns:
            List of matches
        """
        query = self.session.query(Match).filter(Match.asset_id == asset_id)
        if status:
            query = query.filter(Match.status == status)

        return query.order_by(Match.priority_score.desc()).all()

    def get_matches_by_kev(self, kev_entry_id: int, status: Optional[MatchStatus] = None) -> List[Match]:
        """
        Get all matches for a specific KEV entry

        Args:
            kev_entry_id: KEV entry ID
            status: Optional status filter

        Returns:
            List of matches
        """
        query = self.session.query(Match).filter(Match.kev_entry_id == kev_entry_id)
        if status:
            query = query.filter(Match.status == status)

        return query.order_by(Match.priority_score.desc()).all()

    def mark_false_positive(self, match_id: int, reason: str):
        """
        Mark a match as false positive

        Args:
            match_id: Match ID
            reason: Reason for false positive
        """
        match = self.session.query(Match).filter_by(id=match_id).first()
        if not match:
            raise ValueError(f"Match {match_id} not found")

        match.status = MatchStatus.FALSE_POSITIVE
        match.false_positive_reason = reason
        match.updated_at = datetime.utcnow()

        self.session.commit()
        logger.info(f"Match {match_id} marked as false positive: {reason}")

    def mark_mitigated(self, match_id: int, notes: str):
        """
        Mark a match as mitigated

        Args:
            match_id: Match ID
            notes: Mitigation notes
        """
        match = self.session.query(Match).filter_by(id=match_id).first()
        if not match:
            raise ValueError(f"Match {match_id} not found")

        match.status = MatchStatus.MITIGATED
        match.mitigation_notes = notes
        match.mitigated_at = datetime.utcnow()
        match.updated_at = datetime.utcnow()

        self.session.commit()
        logger.info(f"Match {match_id} marked as mitigated")

    def get_new_matches_since(self, since: datetime) -> List[Match]:
        """
        Get matches created since a specific time

        Args:
            since: Datetime to filter from

        Returns:
            List of new matches
        """
        return self.session.query(Match).filter(
            Match.created_at >= since
        ).order_by(Match.priority_score.desc()).all()
