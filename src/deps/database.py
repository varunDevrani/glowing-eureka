


from src.database.connect import sessionLocal
from sqlalchemy.exc import SQLAlchemyError


def get_db():
	db = sessionLocal()
	try:
		yield db
		db.commit()
	except SQLAlchemyError:
		db.rollback()
		raise
	finally:
		db.close()

