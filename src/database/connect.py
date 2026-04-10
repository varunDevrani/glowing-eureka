


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.core.config import settings

engine = create_engine(
    settings.DATABASE_URL.get_secret_value(),
    pool_pre_ping=True,
    connect_args={
        "prepare_threshold": 0
    }
)

sessionLocal = sessionmaker(
	bind=engine,
	autoflush=False,
	autocommit=False
)
