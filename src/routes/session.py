



from datetime import datetime, timezone
from http import HTTPStatus
from fastapi import APIRouter, Depends
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from src.deps.auth import get_current_user
from src.deps.database import get_db
from src.models.refresh_token import RefreshToken
from src.models.user import User
from src.schemas.api_response import SuccessResponse
from src.schemas.session import SessionResponse, SessionsResponse


router = APIRouter(
	prefix="/sessions",
	tags=["Sessions"]
)


@router.get(
	"/me",
	status_code=HTTPStatus.OK,
	response_model=SuccessResponse[SessionsResponse]
)
def get_current_sessions(
	user: User = Depends(get_current_user),
	db: Session = Depends(get_db)
) -> SuccessResponse[SessionsResponse]:
	# Step 1 — find the max created_at per family_id
	subq = (
	    select(
	        RefreshToken.family_id,
	        func.max(RefreshToken.created_at).label("max_created_at")
	    )
	    .where(
	        RefreshToken.user_id == user.uid,
	        RefreshToken.is_used.is_(False),
	        RefreshToken.expires_at > datetime.now(timezone.utc)
	    )
	    .group_by(RefreshToken.family_id)
	    .subquery()
	)
	
	# Step 2 — join back to get full row
	stmt = (
	    select(RefreshToken)
	    .join(
	        subq,
	        and_(
	            RefreshToken.family_id == subq.c.family_id,
	            RefreshToken.created_at == subq.c.max_created_at
	        )
	    )
	)
	
	sessions = db.scalars(stmt).all()
	
	return SuccessResponse[SessionsResponse](
		message="All sessions for current user fetch successfully.",
		data=SessionsResponse(
			sessions=[
				SessionResponse.model_validate(sess) for sess in sessions
			]
		)
	)
