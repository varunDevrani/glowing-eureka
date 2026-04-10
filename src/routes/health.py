



from datetime import datetime, timezone
from http import HTTPStatus
from fastapi import APIRouter


router = APIRouter(
	prefix="",
	tags=["Health"]
)

@router.get(
	"/healthz",
	status_code=HTTPStatus.OK,
	response_model=dict
)
def health_check():
	return {
		"status": "ok",
		"time": datetime.now(timezone.utc)
	}

