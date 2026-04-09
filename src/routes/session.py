



from datetime import datetime, timezone
from http import HTTPStatus
from typing import Union
from uuid import UUID
from fastapi import APIRouter, Depends
from sqlalchemy import and_, func, select, update
from sqlalchemy.orm import Session

from src.deps.auth import get_current_user
from src.deps.database import get_db
from src.errors.app_exception import NotFoundException
from src.models.refresh_token import RefreshToken
from src.models.user import User
from src.schemas.api_response import SuccessResponse
from src.schemas.session import SessionResponse, SessionsResponse
from src.models.token_family import TokenFamily
from src.schemas.auth import RefreshRequest
from src.services.token import hash_token

router = APIRouter(
	prefix="/sessions",
	tags=["Sessions"]
)


@router.post(
    "",
    status_code=HTTPStatus.OK,
    response_model=SuccessResponse[SessionsResponse],
)
def get_current_sessions(
    payload: RefreshRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SuccessResponse[SessionsResponse]:
    now = datetime.now(timezone.utc)

    token_hash = hash_token(payload.refresh_token)

    current_family_id: Union[UUID, None] = db.scalar(
        select(RefreshToken.family_id)
        .join(TokenFamily, TokenFamily.uid == RefreshToken.family_id)
        .where(
            RefreshToken.token_hash == token_hash,
            TokenFamily.user_id == user.uid,
            TokenFamily.revoked_at.is_(None),
        )
    )

    subq = (
        select(
            RefreshToken.family_id,
            func.max(RefreshToken.created_at).label("max_created_at"),
        )
        .join(TokenFamily, TokenFamily.uid == RefreshToken.family_id)
        .where(
            TokenFamily.user_id == user.uid,
            TokenFamily.revoked_at.is_(None),
            RefreshToken.used_at.is_(None),
            RefreshToken.expires_at > now,
        )
        .group_by(RefreshToken.family_id)
        .subquery()
    )

    stmt = (
        select(RefreshToken)
        .join(
            subq,
            and_(
                RefreshToken.family_id == subq.c.family_id,
                RefreshToken.created_at == subq.c.max_created_at,
            ),
        )
        .order_by(RefreshToken.created_at.desc())
    )

    rows = db.scalars(stmt).all()

    sessions = []
    for row in rows:
        s = SessionResponse.model_validate(row)
        s.current = (row.family_id == current_family_id)
        sessions.append(s)

    return SuccessResponse[SessionsResponse](
        message="All sessions for current user fetched successfully.",
        data=SessionsResponse(sessions=sessions),
    )



@router.delete(
	"/{family_id}",
	status_code=HTTPStatus.NO_CONTENT,
	response_model=None
)
def revoke_session_by_family_id(
	family_id: UUID,
	user: User = Depends(get_current_user),
	db: Session = Depends(get_db)
) -> None:
	sessions = db.scalars(select(TokenFamily).where(TokenFamily.uid == family_id, TokenFamily.user_id == user.uid)).all()
	
	if len(sessions) <= 0:
		raise NotFoundException(
			message="User has none tokens with the provided family_id"
		)

	for sess in sessions:
		sess.revoked_at = datetime.now(timezone.utc)


@router.delete(
    "",
    status_code=HTTPStatus.NO_CONTENT,
    response_model=None
)
def revoke_all_sessions(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> None:
    db.execute(update(TokenFamily).where(TokenFamily.user_id == user.uid, TokenFamily.revoked_at.is_(None)).values(revoked_at=datetime.now(timezone.utc)))


	
