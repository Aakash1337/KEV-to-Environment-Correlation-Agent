"""
Database connection and session management
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager
from pathlib import Path
import logging

from .models import Base

logger = logging.getLogger(__name__)


class Database:
    """Database manager for KEV Mapper"""

    def __init__(self, db_path: str = "data/kev_mapper.db"):
        """
        Initialize database connection

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path

        # Ensure directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        # Create engine
        self.engine = create_engine(
            f"sqlite:///{db_path}",
            echo=False,  # Set to True for SQL debugging
            connect_args={"check_same_thread": False}  # For SQLite
        )

        # Create session factory
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )

        logger.info(f"Database initialized at {db_path}")

    def create_tables(self):
        """Create all tables if they don't exist"""
        Base.metadata.create_all(bind=self.engine)
        logger.info("Database tables created/verified")

    def drop_tables(self):
        """Drop all tables (use with caution!)"""
        Base.metadata.drop_all(bind=self.engine)
        logger.warning("All database tables dropped")

    @contextmanager
    def get_session(self) -> Session:
        """
        Get a database session with automatic cleanup

        Usage:
            with db.get_session() as session:
                # use session
                pass
        """
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            session.close()


# Global database instance
_db_instance = None


def get_db(config_path: str = None) -> Database:
    """
    Get or create global database instance

    Args:
        config_path: Optional path to database file

    Returns:
        Database instance
    """
    global _db_instance
    if _db_instance is None:
        db_path = config_path or "data/kev_mapper.db"
        _db_instance = Database(db_path)
        _db_instance.create_tables()
    return _db_instance
