from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.config import settings
from src.database.connect import engine
from src.errors.handler import register_exception_handlers
from src.models.base import Base
from src.routes.auth import router as auth_router
from src.routes.session import router as session_router

app = FastAPI()

app.add_middleware(
	CORSMiddleware,
	allow_origins=[settings.FRONTEND_URL],
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
)


@app.on_event("startup")
def startup():
	Base.metadata.create_all(
		bind=engine
	)

register_exception_handlers(app)


app.include_router(router=auth_router, prefix="/api/v1")
app.include_router(router=session_router, prefix="/api/v1")
