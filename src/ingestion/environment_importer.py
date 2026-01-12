"""
Environment data import from various sources
"""
import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from ..database import Asset, Finding, AuditLog, AssetCriticality, AssetEnvironment, ExposureLevel
from ..config import Config

logger = logging.getLogger(__name__)


class EnvironmentImporter:
    """Handles import of environment data from various sources"""

    def __init__(self, config: Config, db_session: Session):
        """
        Initialize environment importer

        Args:
            config: Application configuration
            db_session: Database session
        """
        self.config = config
        self.session = db_session

    def import_file(self, file_path: str, source_type: str) -> Dict:
        """
        Import environment data from file

        Args:
            file_path: Path to import file
            source_type: Type of source (nessus_csv, qualys_csv, asset_inventory, sbom)

        Returns:
            Dictionary with import statistics
        """
        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            raise FileNotFoundError(f"Import file not found: {file_path}")

        logger.info(f"Importing {source_type} from {file_path}")

        if source_type == "nessus_csv":
            return self.import_nessus_csv(file_path)
        elif source_type == "qualys_csv":
            return self.import_qualys_csv(file_path)
        elif source_type == "asset_inventory":
            return self.import_asset_inventory(file_path)
        elif source_type == "sbom":
            return self.import_sbom(file_path)
        else:
            raise ValueError(f"Unsupported source type: {source_type}")

    def get_or_create_asset(self, hostname: str, ip_address: Optional[str] = None) -> Asset:
        """
        Get existing asset or create new one

        Args:
            hostname: Asset hostname
            ip_address: Asset IP address

        Returns:
            Asset object
        """
        # Try to find by hostname or IP
        asset = self.session.query(Asset).filter(
            (Asset.hostname == hostname) | (Asset.ip_address == ip_address)
        ).first()

        if not asset:
            asset = Asset(
                hostname=hostname,
                ip_address=ip_address,
                criticality=AssetCriticality.MEDIUM,
                environment=AssetEnvironment.PRODUCTION,
                exposure=ExposureLevel.INTERNAL_ONLY
            )
            self.session.add(asset)
            self.session.flush()  # Get the ID
            logger.debug(f"Created new asset: {hostname}")

        return asset

    def import_nessus_csv(self, file_path: str) -> Dict:
        """
        Import Nessus CSV export

        Expected columns: Host, IP, CVE, Plugin ID, Name, Severity, Solution

        Args:
            file_path: Path to Nessus CSV file

        Returns:
            Import statistics
        """
        start_time = datetime.utcnow()
        findings_count = 0
        assets_created = 0

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    hostname = row.get('Host', '').strip()
                    ip_address = row.get('IP', '').strip()
                    cve = row.get('CVE', '').strip()
                    plugin_id = row.get('Plugin ID', '').strip()

                    if not hostname and not ip_address:
                        continue

                    # Get or create asset
                    asset = self.get_or_create_asset(hostname or ip_address, ip_address)
                    if asset.id and not self.session.query(Asset).filter_by(id=asset.id).first():
                        assets_created += 1

                    # Create finding if CVE exists
                    if cve and cve != 'N/A':
                        finding = Finding(
                            asset_id=asset.id,
                            cve_id=cve,
                            product=row.get('Name', ''),
                            detected_version=None,  # Nessus CSV may not have version
                            evidence_blob={
                                "plugin_id": plugin_id,
                                "name": row.get('Name', ''),
                                "severity": row.get('Severity', ''),
                                "solution": row.get('Solution', ''),
                                "raw_row": row
                            },
                            source="nessus",
                            source_id=plugin_id,
                            severity=row.get('Severity', ''),
                            detected_at=datetime.utcnow()
                        )
                        self.session.add(finding)
                        findings_count += 1

            self.session.commit()

            # Log audit entry
            audit_log = AuditLog(
                operation="import",
                details={
                    "source_type": "nessus_csv",
                    "file": file_path,
                    "findings_imported": findings_count,
                    "assets_created": assets_created,
                    "duration_seconds": (datetime.utcnow() - start_time).total_seconds()
                },
                result="success"
            )
            self.session.add(audit_log)
            self.session.commit()

            logger.info(f"Nessus import completed: {findings_count} findings, {assets_created} new assets")

            return {
                "status": "success",
                "source": "nessus_csv",
                "findings_imported": findings_count,
                "assets_created": assets_created
            }

        except Exception as e:
            self.session.rollback()
            logger.error(f"Nessus import failed: {e}", exc_info=True)
            raise

    def import_qualys_csv(self, file_path: str) -> Dict:
        """
        Import Qualys CSV export

        Expected columns: DNS, IP, CVE ID, Title, Severity

        Args:
            file_path: Path to Qualys CSV file

        Returns:
            Import statistics
        """
        start_time = datetime.utcnow()
        findings_count = 0
        assets_created = 0

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    hostname = row.get('DNS', '').strip()
                    ip_address = row.get('IP', '').strip()
                    cve = row.get('CVE ID', '').strip()

                    if not hostname and not ip_address:
                        continue

                    # Get or create asset
                    asset = self.get_or_create_asset(hostname or ip_address, ip_address)
                    if not self.session.query(Asset).filter_by(id=asset.id).first():
                        assets_created += 1

                    # Create finding
                    if cve and cve != 'N/A':
                        finding = Finding(
                            asset_id=asset.id,
                            cve_id=cve,
                            product=row.get('Title', ''),
                            detected_version=None,
                            evidence_blob={
                                "title": row.get('Title', ''),
                                "severity": row.get('Severity', ''),
                                "raw_row": row
                            },
                            source="qualys",
                            source_id=cve,
                            severity=row.get('Severity', ''),
                            detected_at=datetime.utcnow()
                        )
                        self.session.add(finding)
                        findings_count += 1

            self.session.commit()

            # Log audit entry
            audit_log = AuditLog(
                operation="import",
                details={
                    "source_type": "qualys_csv",
                    "file": file_path,
                    "findings_imported": findings_count,
                    "assets_created": assets_created,
                    "duration_seconds": (datetime.utcnow() - start_time).total_seconds()
                },
                result="success"
            )
            self.session.add(audit_log)
            self.session.commit()

            logger.info(f"Qualys import completed: {findings_count} findings, {assets_created} new assets")

            return {
                "status": "success",
                "source": "qualys_csv",
                "findings_imported": findings_count,
                "assets_created": assets_created
            }

        except Exception as e:
            self.session.rollback()
            logger.error(f"Qualys import failed: {e}", exc_info=True)
            raise

    def import_asset_inventory(self, file_path: str) -> Dict:
        """
        Import asset inventory CSV/JSON

        Expected columns: hostname, ip, os, criticality, environment, exposure, owner, tags

        Args:
            file_path: Path to asset inventory file

        Returns:
            Import statistics
        """
        start_time = datetime.utcnow()
        assets_imported = 0

        try:
            file_ext = Path(file_path).suffix.lower()

            if file_ext == '.json':
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    assets_data = data if isinstance(data, list) else data.get('assets', [])
            elif file_ext == '.csv':
                with open(file_path, 'r') as f:
                    reader = csv.DictReader(f)
                    assets_data = list(reader)
            else:
                raise ValueError(f"Unsupported file format: {file_ext}")

            for asset_data in assets_data:
                hostname = asset_data.get('hostname', '').strip()
                ip_address = asset_data.get('ip', '').strip()

                if not hostname and not ip_address:
                    continue

                # Parse enums
                criticality = self._parse_criticality(asset_data.get('criticality', 'medium'))
                environment = self._parse_environment(asset_data.get('environment', 'production'))
                exposure = self._parse_exposure(asset_data.get('exposure', 'internal_only'))

                # Get or create asset
                asset = self.get_or_create_asset(hostname, ip_address)

                # Update asset details
                asset.operating_system = asset_data.get('os', asset_data.get('operating_system'))
                asset.os_version = asset_data.get('os_version')
                asset.owner = asset_data.get('owner')
                asset.criticality = criticality
                asset.environment = environment
                asset.exposure = exposure
                asset.description = asset_data.get('description')
                asset.location = asset_data.get('location')

                # Parse tags
                tags = asset_data.get('tags', '')
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(',') if t.strip()]
                asset.tags = tags

                asset.last_updated = datetime.utcnow()
                assets_imported += 1

            self.session.commit()

            # Log audit entry
            audit_log = AuditLog(
                operation="import",
                details={
                    "source_type": "asset_inventory",
                    "file": file_path,
                    "assets_imported": assets_imported,
                    "duration_seconds": (datetime.utcnow() - start_time).total_seconds()
                },
                result="success"
            )
            self.session.add(audit_log)
            self.session.commit()

            logger.info(f"Asset inventory import completed: {assets_imported} assets")

            return {
                "status": "success",
                "source": "asset_inventory",
                "assets_imported": assets_imported
            }

        except Exception as e:
            self.session.rollback()
            logger.error(f"Asset inventory import failed: {e}", exc_info=True)
            raise

    def import_sbom(self, file_path: str) -> Dict:
        """
        Import SBOM (CycloneDX or SPDX format)

        Args:
            file_path: Path to SBOM file

        Returns:
            Import statistics
        """
        start_time = datetime.utcnow()
        findings_count = 0

        try:
            with open(file_path, 'r') as f:
                sbom_data = json.load(f)

            # Determine SBOM format
            if 'bomFormat' in sbom_data and sbom_data['bomFormat'] == 'CycloneDX':
                return self._import_cyclonedx(sbom_data, file_path)
            elif 'spdxVersion' in sbom_data:
                return self._import_spdx(sbom_data, file_path)
            else:
                raise ValueError("Unknown SBOM format")

        except Exception as e:
            self.session.rollback()
            logger.error(f"SBOM import failed: {e}", exc_info=True)
            raise

    def _import_cyclonedx(self, sbom_data: Dict, file_path: str) -> Dict:
        """Import CycloneDX SBOM"""
        # Simplified implementation - would need full CycloneDX parsing
        metadata = sbom_data.get('metadata', {})
        component = metadata.get('component', {})

        # Create/update asset
        hostname = component.get('name', Path(file_path).stem)
        asset = self.get_or_create_asset(hostname)

        # Process components
        findings_count = 0
        for comp in sbom_data.get('components', []):
            # Check for vulnerabilities
            vulnerabilities = comp.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                cve_id = vuln.get('id')
                if cve_id and cve_id.startswith('CVE-'):
                    finding = Finding(
                        asset_id=asset.id,
                        cve_id=cve_id,
                        product=comp.get('name'),
                        detected_version=comp.get('version'),
                        evidence_blob={
                            "sbom_source": "cyclonedx",
                            "component": comp,
                            "vulnerability": vuln
                        },
                        source="sbom",
                        source_id=cve_id,
                        detected_at=datetime.utcnow()
                    )
                    self.session.add(finding)
                    findings_count += 1

        self.session.commit()

        return {
            "status": "success",
            "source": "cyclonedx_sbom",
            "findings_imported": findings_count
        }

    def _import_spdx(self, sbom_data: Dict, file_path: str) -> Dict:
        """Import SPDX SBOM"""
        # Simplified implementation
        hostname = sbom_data.get('name', Path(file_path).stem)
        asset = self.get_or_create_asset(hostname)

        findings_count = 0
        # SPDX parsing would go here
        self.session.commit()

        return {
            "status": "success",
            "source": "spdx_sbom",
            "findings_imported": findings_count
        }

    def _parse_criticality(self, value: str) -> AssetCriticality:
        """Parse criticality string to enum"""
        value_lower = value.lower()
        if value_lower == "critical":
            return AssetCriticality.CRITICAL
        elif value_lower == "high":
            return AssetCriticality.HIGH
        elif value_lower == "low":
            return AssetCriticality.LOW
        else:
            return AssetCriticality.MEDIUM

    def _parse_environment(self, value: str) -> AssetEnvironment:
        """Parse environment string to enum"""
        value_lower = value.lower()
        if value_lower in ("prod", "production"):
            return AssetEnvironment.PRODUCTION
        elif value_lower in ("dev", "development"):
            return AssetEnvironment.DEVELOPMENT
        elif value_lower == "staging":
            return AssetEnvironment.STAGING
        elif value_lower == "test":
            return AssetEnvironment.TEST
        else:
            return AssetEnvironment.PRODUCTION

    def _parse_exposure(self, value: str) -> ExposureLevel:
        """Parse exposure string to enum"""
        value_lower = value.lower()
        if value_lower in ("internet", "internet_facing", "public"):
            return ExposureLevel.INTERNET_FACING
        elif value_lower in ("vpn", "vpn_only"):
            return ExposureLevel.VPN_ONLY
        else:
            return ExposureLevel.INTERNAL_ONLY
