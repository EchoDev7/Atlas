from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from backend.config import settings

settings.DATA_DIR.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
    # Lightweight SQLite migration for existing deployments
    with engine.begin() as connection:
        table_exists = connection.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='vpn_users'")
        ).fetchone()
        if not table_exists:
            return

        columns = connection.execute(text("PRAGMA table_info(vpn_users)")).fetchall()
        column_names = {col[1] for col in columns}
        if "max_devices" not in column_names:
            connection.execute(
                text("ALTER TABLE vpn_users ADD COLUMN max_devices INTEGER NOT NULL DEFAULT 1")
            )
