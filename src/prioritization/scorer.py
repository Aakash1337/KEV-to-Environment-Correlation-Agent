"""
Prioritization scorer for KEV matches
"""
import logging
from datetime import datetime
from typing import Dict
from sqlalchemy.orm import Session

from ..database import Match, Asset, KEVEntry
from ..config import Config

logger = logging.getLogger(__name__)


class PrioritizationScorer:
    """
    Scores matches based on multiple factors to create a priority queue
    """

    def __init__(self, config: Config, db_session: Session):
        """
        Initialize prioritization scorer

        Args:
            config: Application configuration
            db_session: Database session
        """
        self.config = config
        self.session = db_session

        # Load scoring weights from config
        self.weights = {
            "asset_criticality": config.prioritization.weights.asset_criticality,
            "exposure": config.prioritization.weights.exposure,
            "kev_age": config.prioritization.weights.kev_age,
            "finding_age": config.prioritization.weights.finding_age,
        }

        self.criticality_scores = {
            "critical": config.prioritization.criticality_scores.critical,
            "high": config.prioritization.criticality_scores.high,
            "medium": config.prioritization.criticality_scores.medium,
            "low": config.prioritization.criticality_scores.low,
        }

        self.exposure_scores = {
            "internet_facing": config.prioritization.exposure_scores.internet_facing,
            "vpn_only": config.prioritization.exposure_scores.vpn_only,
            "internal_only": config.prioritization.exposure_scores.internal_only,
        }

    def score_match(self, match: Match) -> float:
        """
        Calculate priority score for a match

        Args:
            match: Match object

        Returns:
            Priority score (0-100)
        """
        # Load related objects
        asset = self.session.query(Asset).filter_by(id=match.asset_id).first()
        kev_entry = self.session.query(KEVEntry).filter_by(id=match.kev_entry_id).first()

        if not asset or not kev_entry:
            logger.warning(f"Match {match.id} missing asset or KEV entry")
            return 0.0

        # Calculate component scores
        scores = {
            "asset_criticality": self._score_asset_criticality(asset),
            "exposure": self._score_exposure(asset),
            "kev_age": self._score_kev_age(kev_entry),
            "finding_age": self._score_finding_age(match),
        }

        # Calculate weighted total
        total_score = sum(
            scores[factor] * self.weights[factor]
            for factor in scores.keys()
        )

        # Normalize to 0-100 scale
        normalized_score = min(100.0, total_score * 10)

        # Store the breakdown
        match.priority_score = normalized_score
        match.priority_factors = {
            "scores": scores,
            "weights": self.weights,
            "final_score": normalized_score
        }

        logger.debug(f"Match {match.id} scored: {normalized_score:.2f}")

        return normalized_score

    def _score_asset_criticality(self, asset: Asset) -> float:
        """
        Score based on asset criticality

        Args:
            asset: Asset object

        Returns:
            Criticality score (0-10)
        """
        criticality_value = asset.criticality.value if asset.criticality else "medium"
        return self.criticality_scores.get(criticality_value, 4)

    def _score_exposure(self, asset: Asset) -> float:
        """
        Score based on asset exposure

        Args:
            asset: Asset object

        Returns:
            Exposure score (0-10)
        """
        exposure_value = asset.exposure.value if asset.exposure else "internal_only"
        return self.exposure_scores.get(exposure_value, 2)

    def _score_kev_age(self, kev_entry: KEVEntry) -> float:
        """
        Score based on how long the KEV has been published (newer = higher priority)

        Args:
            kev_entry: KEV entry

        Returns:
            Age score (0-10)
        """
        if not kev_entry.date_added:
            return 5.0  # Default if no date

        days_since_added = (datetime.utcnow() - kev_entry.date_added).days

        # Score higher for newer KEVs (decay over time)
        if days_since_added <= 7:
            return 10.0
        elif days_since_added <= 30:
            return 8.0
        elif days_since_added <= 90:
            return 6.0
        elif days_since_added <= 180:
            return 4.0
        else:
            return 2.0

    def _score_finding_age(self, match: Match) -> float:
        """
        Score based on how long the finding has been known (newer = higher)

        Args:
            match: Match object

        Returns:
            Finding age score (0-10)
        """
        if not match.created_at:
            return 5.0

        days_since_match = (datetime.utcnow() - match.created_at).days

        # Newer matches get higher priority
        if days_since_match == 0:
            return 10.0
        elif days_since_match <= 7:
            return 8.0
        elif days_since_match <= 30:
            return 6.0
        else:
            return 4.0

    def score_all_matches(self):
        """
        Score all open matches in the database
        """
        logger.info("Scoring all open matches")

        matches = self.session.query(Match).filter(
            Match.status.in_(["open", "in_progress"])
        ).all()

        for match in matches:
            self.score_match(match)

        self.session.commit()

        logger.info(f"Scored {len(matches)} matches")

    def get_top_priorities(self, limit: int = 10) -> list:
        """
        Get top priority matches

        Args:
            limit: Maximum number of matches to return

        Returns:
            List of top priority matches
        """
        return self.session.query(Match).filter(
            Match.status == "open"
        ).order_by(
            Match.priority_score.desc()
        ).limit(limit).all()

    def get_priority_explanation(self, match: Match) -> str:
        """
        Generate human-readable explanation of priority score

        Args:
            match: Match object

        Returns:
            Explanation string
        """
        if not match.priority_factors:
            return "Priority score not calculated"

        factors = match.priority_factors.get("scores", {})

        explanation_parts = [
            f"Priority Score: {match.priority_score:.1f}/100",
            "",
            "Contributing Factors:",
        ]

        # Asset criticality
        asset = self.session.query(Asset).filter_by(id=match.asset_id).first()
        if asset:
            explanation_parts.append(
                f"  - Asset Criticality ({asset.criticality.value}): {factors.get('asset_criticality', 0):.1f}/10"
            )
            explanation_parts.append(
                f"  - Exposure ({asset.exposure.value}): {factors.get('exposure', 0):.1f}/10"
            )

        # KEV age
        kev_entry = self.session.query(KEVEntry).filter_by(id=match.kev_entry_id).first()
        if kev_entry:
            explanation_parts.append(
                f"  - KEV Recency: {factors.get('kev_age', 0):.1f}/10"
            )

        # Finding age
        explanation_parts.append(
            f"  - Finding Recency: {factors.get('finding_age', 0):.1f}/10"
        )

        return "\n".join(explanation_parts)
