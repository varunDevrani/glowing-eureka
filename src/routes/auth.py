from datetime import datetime, timezone
from http import HTTPStatus

from fastapi import APIRouter, Depends, Request
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import src.services.auth as services
from src.core.enums import UserStatus
from src.deps.auth import get_current_user
from src.deps.database import get_db
from src.errors.app_exception import (
    AccountDeactivatedException,
    AuthenticationException,
    AuthorizationException,
    BadRequestException,
    ConflictException,
    NotFoundException,
)
from src.models.refresh_token import RefreshToken
from src.models.user import User
from src.schemas.api_response import SuccessResponse
from src.schemas.auth import (
    DeactivateRequest,
    LoginRequest,
    RefreshRequest,
    SignupRequest,
    TokenResponse,
)
from src.schemas.user import UserResponse
from src.utils.hash import hash_password, verify_password


router = APIRouter(
	prefix="/auth",
	tags=["Authentication"]
)



@router.post(
	path="/signup",
	status_code=HTTPStatus.CREATED,
	response_model=SuccessResponse[UserResponse]
)
def signup(
	payload: SignupRequest,
	db: Session = Depends(get_db)
) -> SuccessResponse[UserResponse]:
	user = User(
		email=payload.email,
		password_hash=hash_password(payload.password)
	)
	db.add(user)
	try:
		db.flush()
	except IntegrityError:
		raise ConflictException(
			message="User with provided email already exists."
		)
	db.refresh(user)

	return SuccessResponse[UserResponse](
		message="User created successfully. Please login.",
		data=UserResponse.model_validate(user)
	)


@router.post(
	"/login",
	status_code=HTTPStatus.OK,
	response_model=SuccessResponse[TokenResponse]
)
def login(
	payload: LoginRequest,
	request: Request,
	db: Session = Depends(get_db)
) -> SuccessResponse[TokenResponse]:
	user = services.authenticate_user_via_email(
		db.scalar(select(User).where(User.email == payload.email)),
		payload.password)

	if user.status == UserStatus.BANNED:
		raise AuthorizationException(
			message="Your account has been suspended. Contact support.",
		)

	if user.status == UserStatus.DEACTIVATED:
		raise AccountDeactivatedException()

	access_token, raw_refresh_token, refresh_token = services.create_tokens(
		user,
		request.headers.get("user-agent"),
		request.client.host if request.client else None,
	)

	db.add(refresh_token)
	db.flush()

	return SuccessResponse[TokenResponse](
		message="User logged in successfully.",
		data=TokenResponse(
			access_token=access_token,
			refresh_token=raw_refresh_token
		)
	)



@router.post(
	"/refresh",
	status_code=HTTPStatus.OK,
	response_model=SuccessResponse[TokenResponse]
)
def refresh(
	payload: RefreshRequest,
	request: Request,
	db: Session = Depends(get_db)
) -> SuccessResponse[TokenResponse]:
	refresh_token = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == services.hash_token(payload.refresh_token)))

	if refresh_token is None:
		raise AuthenticationException(
			message="Invalid refresh token."
		)

	if refresh_token.is_used:
		db.execute(update(RefreshToken).where(RefreshToken.family_id == refresh_token.family_id, RefreshToken.is_used.is_(False)).values(is_used=True))
		db.commit()
		raise AuthenticationException(
			message="Token reuse detected. All sessions revoked.",
		)

	if refresh_token.expires_at < datetime.now(timezone.utc):
		raise AuthenticationException(
			message="Refresh token expired."
		)

	user = db.scalar(select(User).where(User.uid == refresh_token.user_id))
	if user is None:
		raise NotFoundException(
			message="User not found."
		)

	if user.status == UserStatus.BANNED:
		db.execute(update(RefreshToken).where(RefreshToken.family_id == refresh_token.family_id, RefreshToken.is_used.is_(False)).values(is_used=True))
		db.commit()
		raise AuthorizationException(
			message="Your account has been suspended. Contact support.",
		)

	if user.status == UserStatus.DEACTIVATED:
		refresh_token.is_used = True
		db.commit()
		raise AccountDeactivatedException()

	refresh_token.is_used = True

	access_token, raw_refresh_token, refresh_token = services.create_tokens(
		user,
		request.headers.get("user-agent"),
		request.client.host if request.client else None,
		refresh_token.family_id
	)

	db.add(refresh_token)
	db.flush()

	return SuccessResponse[TokenResponse](
		message="Token refreshed successfully.",
		data=TokenResponse(
			access_token=access_token,
			refresh_token=raw_refresh_token
		)
	)



@router.post(
	"/logout",
	status_code=HTTPStatus.OK,
	response_model=SuccessResponse[None]
)
def logout(
	payload: RefreshRequest,
	db: Session = Depends(get_db)
) -> SuccessResponse[None]:
	refresh_token = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == services.hash_token(payload.refresh_token)))
	
	if refresh_token is not None:
		db.execute(delete(RefreshToken).where(RefreshToken.family_id == refresh_token.family_id))
		db.flush()

	return SuccessResponse[None](
		message="User logged out successfully."
	)


@router.post(
	"/reactivate",
	status_code=HTTPStatus.OK,
	response_model=SuccessResponse[None]
)
def reactivate(
	payload: LoginRequest,
	db: Session = Depends(get_db)
) -> SuccessResponse[None]:
	user = services.authenticate_user_via_email(
		db.scalar(select(User).where(User.email == payload.email)),
		payload.password)

	if user.status == UserStatus.BANNED:
		raise AuthorizationException(
			message="Your account has been suspended. Contact support.",
		)

	if user.status == UserStatus.ACTIVE:
		raise BadRequestException(
			message="Account is already activated."
		)

	user.status = UserStatus.ACTIVE
	user.deleted_at = None
	db.flush()

	return SuccessResponse[None](
		message="Account reactivated successfully."
	)


@router.post(
	"/deactivate",
	status_code=HTTPStatus.OK,
	response_model=SuccessResponse[None]
)
def deactivate(
	payload: DeactivateRequest,
	user: User = Depends(get_current_user),
	db: Session = Depends(get_db)
) -> SuccessResponse[None]:
	if not verify_password(user.password_hash, payload.password):
		raise AuthenticationException(
			message="Invalid password."
		)

	if user.status == UserStatus.BANNED:
		raise AuthorizationException(
			message="Your account has been suspended. Contact support.",
		)

	if user.status == UserStatus.DEACTIVATED:
		raise AccountDeactivatedException(
			message="Your account is already deactivated.",
		)

	db.execute(update(RefreshToken).where(RefreshToken.user_id == user.uid, RefreshToken.is_used.is_(False)).values(is_used=True))

	user.deleted_at = datetime.now(timezone.utc)
	user.status = UserStatus.DEACTIVATED
	db.flush()

	return SuccessResponse[None](
		message="User deactivated successfully."
	)
