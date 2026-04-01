from fastapi import FastAPI

from src.database.connect import engine
from src.errors.handler import register_exception_handlers
from src.models.base import Base
from src.routes.auth import router as auth_router

app = FastAPI()


@app.on_event("startup")
def startup():
	Base.metadata.create_all(
		bind=engine
	)

register_exception_handlers(app)


app.include_router(router=auth_router, prefix="/api/v1")

