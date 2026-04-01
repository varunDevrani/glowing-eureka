


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.core.config import settings


engine = create_engine(settings.DATABASE_URL.get_secret_value())

sessionLocal = sessionmaker(
	bind=engine,
	autoflush=False,
	autocommit=False
)
