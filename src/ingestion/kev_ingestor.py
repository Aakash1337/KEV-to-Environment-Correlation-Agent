"""
KEV catalog ingestion and processing
"""
import requests
import hashlib
import json
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from sqlalchemy.orm import Session

from ..database import KEVEntry, KEVSnapshot, AuditLog
from ..config import Config

logger = logging.getLogger(__name__)


class KEVIngestor:
    """Handles KEV catalog ingestion from CISA"""

    def __init__(self, config: Config, db_session: Session):
        """
        Initialize KEV ingestor

        Args:
            config: Application configuration
            db_session: Database session
        """
        self.config = config
        self.session = db_session
        self.kev_url = config.kev.source_url
        self.github_mirror = config.kev.github_mirror

    def fetch_kev_data(self, use_mirror: bool = False) -> Dict:
        """
        Fetch KEV data from CISA or GitHub mirror

        Args:
            use_mirror: Use GitHub mirror instead of primary source

        Returns:
            KEV catalog as dictionary

        Raises:
            requests.RequestException: If fetch fails
        """
        url = self.github_mirror if use_mirror else self.kev_url

        logger.info(f"Fetching KEV data from {url}")

        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            logger.info(f"Successfully fetched KEV data: {len(data.get('vulnerabilities', []))} entries")
            return data
        except requests.RequestException as e:
            logger.error(f"Failed to fetch KEV data from {url}: {e}")
            if not use_mirror:
                logger.info("Attempting to fetch from GitHub mirror")
                return self.fetch_kev_data(use_mirror=True)
            raise

    def calculate_snapshot_id(self, kev_data: Dict) -> str:
        """
        Calculate unique snapshot ID based on KEV data

        Args:
            kev_data: KEV catalog data

        Returns:
            SHA256 hash of the data
        """
        # Sort and serialize for consistent hashing
        serialized = json.dumps(kev_data, sort_keys=True)
        return hashlib.sha256(serialized.encode()).hexdigest()

    def get_latest_snapshot(self) -> Optional[KEVSnapshot]:
        """
        Get the most recent KEV snapshot from database

        Returns:
            Latest snapshot or None if no snapshots exist
        """
        return self.session.query(KEVSnapshot)\
            .order_by(KEVSnapshot.created_at.desc())\
            .first()

    def compare_snapshots(self, current_data: Dict, previous_snapshot: Optional[KEVSnapshot]) -> Tuple[List[str], List[str], List[str]]:
        """
        Compare current KEV data with previous snapshot

        Args:
            current_data: Current KEV data
            previous_snapshot: Previous snapshot record

        Returns:
            Tuple of (new_cves, updated_cves, removed_cves)
        """
        current_cves = {vuln['cveID']: vuln for vuln in current_data.get('vulnerabilities', [])}

        if previous_snapshot is None or previous_snapshot.raw_data is None:
            # First sync - all entries are new
            return list(current_cves.keys()), [], []

        previous_data = previous_snapshot.raw_data
        previous_cves = {vuln['cveID']: vuln for vuln in previous_data.get('vulnerabilities', [])}

        # Find differences
        new_cves = list(set(current_cves.keys()) - set(previous_cves.keys()))
        removed_cves = list(set(previous_cves.keys()) - set(current_cves.keys()))

        # Check for updates (same CVE but different data)
        updated_cves = []
        for cve_id in set(current_cves.keys()) & set(previous_cves.keys()):
            if json.dumps(current_cves[cve_id], sort_keys=True) != json.dumps(previous_cves[cve_id], sort_keys=True):
                updated_cves.append(cve_id)

        logger.info(f"KEV comparison: {len(new_cves)} new, {len(updated_cves)} updated, {len(removed_cves)} removed")

        return new_cves, updated_cves, removed_cves

    def parse_date(self, date_str: str) -> Optional[datetime]:
        """
        Parse date string to datetime

        Args:
            date_str: Date string in YYYY-MM-DD format

        Returns:
            Datetime object or None if parsing fails
        """
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            logger.warning(f"Failed to parse date: {date_str}")
            return None

    def ingest_kev_entry(self, vuln_data: Dict, snapshot_id: str):
        """
        Ingest or update a single KEV entry

        Args:
            vuln_data: Vulnerability data from KEV
            snapshot_id: Current snapshot ID
        """
        cve_id = vuln_data.get('cveID')

        # Check if entry already exists
        existing = self.session.query(KEVEntry).filter_by(cve_id=cve_id).first()

        # Parse dates
        date_added = self.parse_date(vuln_data.get('dateAdded'))
        due_date = self.parse_date(vuln_data.get('dueDate'))

        if existing:
            # Update existing entry
            existing.vendor_project = vuln_data.get('vendorProject')
            existing.product = vuln_data.get('product')
            existing.vulnerability_name = vuln_data.get('vulnerabilityName')
            existing.date_added = date_added
            existing.short_description = vuln_data.get('shortDescription')
            existing.required_action = vuln_data.get('requiredAction')
            existing.due_date = due_date
            existing.known_ransomware_campaign_use = vuln_data.get('knownRansomwareCampaignUse')
            existing.notes = vuln_data.get('notes')
            existing.references = vuln_data.get('cwes', [])  # Store any additional refs
            existing.last_updated = datetime.utcnow()
            existing.snapshot_id = snapshot_id
        else:
            # Create new entry
            entry = KEVEntry(
                cve_id=cve_id,
                vendor_project=vuln_data.get('vendorProject'),
                product=vuln_data.get('product'),
                vulnerability_name=vuln_data.get('vulnerabilityName'),
                date_added=date_added,
                short_description=vuln_data.get('shortDescription'),
                required_action=vuln_data.get('requiredAction'),
                due_date=due_date,
                known_ransomware_campaign_use=vuln_data.get('knownRansomwareCampaignUse'),
                notes=vuln_data.get('notes'),
                references=vuln_data.get('cwes', []),
                snapshot_id=snapshot_id,
            )
            self.session.add(entry)

    def sync(self) -> Dict:
        """
        Perform full KEV sync operation

        Returns:
            Dictionary with sync statistics
        """
        start_time = datetime.utcnow()
        logger.info("Starting KEV sync")

        try:
            # Fetch current KEV data
            kev_data = self.fetch_kev_data()

            # Calculate snapshot ID
            snapshot_id = self.calculate_snapshot_id(kev_data)

            # Check if this snapshot already exists
            existing_snapshot = self.session.query(KEVSnapshot).filter_by(snapshot_id=snapshot_id).first()
            if existing_snapshot:
                logger.info("KEV data unchanged since last sync")
                return {
                    "status": "unchanged",
                    "snapshot_id": snapshot_id,
                    "entry_count": len(kev_data.get('vulnerabilities', []))
                }

            # Get previous snapshot for comparison
            previous_snapshot = self.get_latest_snapshot()

            # Compare with previous
            new_cves, updated_cves, removed_cves = self.compare_snapshots(kev_data, previous_snapshot)

            # Ingest all entries
            for vuln_data in kev_data.get('vulnerabilities', []):
                self.ingest_kev_entry(vuln_data, snapshot_id)

            # Create snapshot record
            catalog_date = self.parse_date(kev_data.get('catalogVersion'))
            snapshot = KEVSnapshot(
                snapshot_id=snapshot_id,
                catalog_version=kev_data.get('catalogVersion'),
                catalog_date=catalog_date,
                entry_count=len(kev_data.get('vulnerabilities', [])),
                new_entries_count=len(new_cves),
                updated_entries_count=len(updated_cves),
                removed_entries_count=len(removed_cves),
                raw_data=kev_data
            )
            self.session.add(snapshot)

            # Log audit entry
            audit_log = AuditLog(
                operation="kev_sync",
                details={
                    "snapshot_id": snapshot_id,
                    "entry_count": len(kev_data.get('vulnerabilities', [])),
                    "new": len(new_cves),
                    "updated": len(updated_cves),
                    "removed": len(removed_cves),
                    "duration_seconds": (datetime.utcnow() - start_time).total_seconds()
                },
                result="success"
            )
            self.session.add(audit_log)

            self.session.commit()

            logger.info(f"KEV sync completed successfully: {len(new_cves)} new, {len(updated_cves)} updated")

            return {
                "status": "success",
                "snapshot_id": snapshot_id,
                "entry_count": len(kev_data.get('vulnerabilities', [])),
                "new_entries": new_cves,
                "updated_entries": updated_cves,
                "removed_entries": removed_cves
            }

        except Exception as e:
            self.session.rollback()
            logger.error(f"KEV sync failed: {e}", exc_info=True)

            # Log failure
            audit_log = AuditLog(
                operation="kev_sync",
                details={
                    "duration_seconds": (datetime.utcnow() - start_time).total_seconds()
                },
                result="failure",
                error_message=str(e)
            )
            self.session.add(audit_log)
            self.session.commit()

            raise
