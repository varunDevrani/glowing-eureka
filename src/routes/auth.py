



from datetime import datetime, timedelta, timezone
import hashlib
from http import HTTPStatus
import secrets
from uuid import uuid4
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, Request

from src.core.config import settings
from src.core.enums import UserStatus
from src.deps.auth import get_current_user
from src.errors.app_exception import AccountDeactivatedException, AuthenticationException, AuthorizationException, BadRequestException, ConflictException
from src.models.refresh_token import RefreshToken
from src.models.user import User
from src.deps.database import get_db
from src.schemas.api_response import SuccessResponse
from src.schemas.user import UserResponse
from src.schemas.auth import DeactivateRequest, LoginRequest, RefreshRequest, SignupRequest, TokenResponse
from src.utils.hash import DUMMY_HASH, hash_password, verify_password
from src.utils.jwt_handler import create_access_token


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
	user = db.scalar(select(User).where(User.email == payload.email))
	if user is not None:
		raise ConflictException(
			message="User with provided email already exists."
		)
	
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
	user = db.scalar(select(User).where(User.email == payload.email))
	if user is None:
		verify_password(DUMMY_HASH, payload.password) # timing attacks
		raise AuthenticationException(
			message="Invalid email or password.",
		)
	
	if not verify_password(user.password_hash, payload.password):
		raise AuthenticationException(
			message="Invalid email or password."
		)
	
	if user.status == UserStatus.BANNED:
		raise AuthorizationException(
			message="Your account has been suspended. Contact support.",
		)
	
	if user.status == UserStatus.DEACTIVATED:
		raise AccountDeactivatedException()
	
	device_info = request.headers.get("User-Agent")
	
	db.execute(update(RefreshToken).where(RefreshToken.user_id == user.uid, RefreshToken.is_used.is_(False), RefreshToken.expires_at > datetime.now(timezone.utc), RefreshToken.device_info == device_info).values(is_used=True))
	
	active_sessions_count = db.scalar(select(func.count()).where(RefreshToken.user_id == user.uid, RefreshToken.is_used.is_(False), RefreshToken.expires_at > datetime.now(timezone.utc))) or 0	
	if active_sessions_count >= settings.MAX_SESSION_PER_USER:
		oldest_session = db.scalar(select(RefreshToken).where(RefreshToken.user_id == user.uid, RefreshToken.is_used.is_(False), RefreshToken.expires_at > datetime.now(timezone.utc)).order_by(RefreshToken.created_at.asc()).limit(1))
		
		if oldest_session:
			oldest_session.is_used = True
	
	family_id = uuid4()
	access_token = create_access_token(user.uid)
	raw_token = secrets.token_urlsafe(32)
	
	new_refresh_token = RefreshToken(
		user_id=user.uid,
		family_id=family_id,
		token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
		expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
		device_info=device_info
	)
	db.add(new_refresh_token)
	db.flush()
	
	return SuccessResponse[TokenResponse](
		message="User logged in successfully.",
		data=TokenResponse(
			access_token=access_token,
			refresh_token=raw_token
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
	refresh_token = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hashlib.sha256(payload.refresh_token.encode()).hexdigest()))
	
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
	
	access_token = create_access_token(user.uid)
	raw_token = secrets.token_urlsafe(32)
	device_info = request.headers.get("User-Agent")
	
	new_refresh_token = RefreshToken(
		user_id=user.uid,
		family_id=refresh_token.family_id,
		token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
		expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
		device_info=device_info
	)
	db.add(new_refresh_token)
	db.flush()
	
	return SuccessResponse[TokenResponse](
		message="User logged in successfully.",
		data=TokenResponse(
			access_token=access_token,
			refresh_token=raw_token
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
	refresh_token = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hashlib.sha256(payload.refresh_token.encode()).hexdigest()))
	
	if refresh_token is None:
		return SuccessResponse[None](
			message="User logged out successfully."
		)

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
	user = db.scalar(select(User).where(User.email == payload.email))
	if user is None:
		verify_password(DUMMY_HASH, payload.password) # timing attacks
		raise AuthenticationException(
			message="Invalid email or password.",
		)
	
	if not verify_password(user.password_hash, payload.password):
		raise AuthenticationException(
			message="Invalid email or password."
		)
	
	if user.status == UserStatus.BANNED:
		raise AuthorizationException(
			message="Your account has been suspended. Contact support.",
		)
	
	if user.status != UserStatus.ACTIVE:
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
	


