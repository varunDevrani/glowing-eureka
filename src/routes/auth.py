from datetime import datetime, timezone
from http import HTTPStatus

from fastapi import APIRouter, Depends, Request, BackgroundTasks
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.core.config import settings
from src.models.mail_verification_token import MailVerificationToken
from src.models.password_reset_token import PasswordResetToken
from src.models.token_family import TokenFamily
import src.services.auth as auth_services
import src.services.token as token_services
import src.services.mail as mail_services
from src.core.enums import UserStatus
from src.deps.auth import get_current_user
from src.deps.database import get_db
from src.errors.app_exception import (
    AccountDeactivatedException,
    AppException,
    AuthenticationException,
    AuthorizationException,
    BadRequestException,
    ConflictException,
)
from src.models.refresh_token import RefreshToken
from src.models.user import User
from src.schemas.api_response import SuccessResponse
from src.schemas.auth import (
    ChangePasswordRequest,
    DeactivateAccountRequest,
    ForgotPasswordRequest,
    LoginRequest,
    ReactivateAccountRequest,
    RefreshRequest,
    ResendVerificationMailRequest,
    ResetPasswordRequest,
    SignupRequest,
    TokenResponse,
    VerifyMailRequest,
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
	request: Request,
	background_tasks: BackgroundTasks,
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
	
	raw_token, mail_verification_token = token_services.create_mail_verification_token(
		user.uid,
		request.headers.get("user-agent"),
		request.client.host if request.client else None,
	)
	
	db.add(mail_verification_token)
	
	# mail_services.send_verification_mail(user.email, f"{settings.FRONTEND_URL}/mail-verification?token={raw_token}")
	background_tasks.add_task(mail_services.send_verification_mail, user.email, f"{settings.FRONTEND_URL}/mail-verification?token={raw_token}")

	return SuccessResponse[UserResponse](
		message="User created successfully. Please verify your email before logging in.",
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
	user = auth_services.authenticate_user_via_email(
		db.scalar(select(User).where(User.email == payload.email)),
		payload.password)
	
	if user.verified_at is None:
		raise AuthorizationException(
			message="Email is not verified. Please verify your email before logging in."
		)

	if user.status == UserStatus.DEACTIVATED:
		raise AccountDeactivatedException()
	
	token_family = TokenFamily(
		user_id=user.uid
	)
	db.add(token_family)
	db.flush()
	db.refresh(token_family)

	access_token, raw_refresh_token, refresh_token = token_services.create_auth_tokens(
		user.uid,
		token_family.uid,
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
def generate_access_token(
	payload: RefreshRequest,
	request: Request,
	db: Session = Depends(get_db)
) -> SuccessResponse[TokenResponse]:
	refresh_token = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_services.hash_token(payload.refresh_token)))
	if refresh_token is None:
		raise AuthenticationException(
			message="Invalid refresh token provided."
		)
		
	token_family = db.scalar(select(TokenFamily).where(TokenFamily.uid == refresh_token.family_id))
	if token_family is None:
		raise AuthenticationException(
			message="Invalid token family provided."
		)
	
	if token_family.revoked_at is not None:
		raise AuthenticationException(
			message="Session ended. Please login again."
		)
	
	if refresh_token.expires_at < datetime.now(timezone.utc):
		raise AuthenticationException(
			message="Refresh token expired."
		)

	if refresh_token.used_at is not None:
		db.execute(update(RefreshToken).where(RefreshToken.family_id == refresh_token.family_id, RefreshToken.used_at.is_(None)).values(used_at=datetime.now(timezone.utc)))
		db.execute(update(TokenFamily).where(TokenFamily.uid == token_family.uid).values(revoked_at=datetime.now(timezone.utc)))
		db.commit()
		raise AuthenticationException(
			message="Token reuse detected. All sessions revoked.",
		)

	user = db.scalar(select(User).where(User.uid == token_family.user_id))
	if user is None:
		raise AppException()

	if user.status == UserStatus.DEACTIVATED:
		refresh_token.used_at = datetime.now(timezone.utc)
		db.commit()
		raise AccountDeactivatedException()

	refresh_token.used_at = datetime.now(timezone.utc)

	access_token, new_raw_refresh_token, new_refresh_token = token_services.create_auth_tokens(
		user.uid,
		token_family.uid,
		request.headers.get("user-agent"),
		request.client.host if request.client else None
	)

	db.add(new_refresh_token)

	return SuccessResponse[TokenResponse](
		message="Token refreshed successfully.",
		data=TokenResponse(
			access_token=access_token,
			refresh_token=new_raw_refresh_token
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
	refresh_token = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_services.hash_token(payload.refresh_token)))
	
	if refresh_token is not None:
		token_family = db.scalar(select(TokenFamily).where(TokenFamily.uid == refresh_token.family_id))
		if token_family is not None and token_family.revoked_at is None:
			token_family.revoked_at = datetime.now(timezone.utc)
		
	return SuccessResponse[None](
		message="User logged out successfully."
	)


@router.post(
	"/reactivate",
	status_code=HTTPStatus.OK,
	response_model=SuccessResponse[None]
)
def reactivate_account	(
	payload: ReactivateAccountRequest,
	db: Session = Depends(get_db)
) -> SuccessResponse[None]:
	user = auth_services.authenticate_user_via_email(
		db.scalar(select(User).where(User.email == payload.email)),
		payload.password)

	if user.status == UserStatus.ACTIVE:
		raise BadRequestException(
			message="Account is already activated."
		)

	user.status = UserStatus.ACTIVE
	user.deleted_at = None

	return SuccessResponse[None](
		message="Account reactivated successfully."
	)


@router.post(
	"/deactivate",
	status_code=HTTPStatus.OK,
	response_model=SuccessResponse[None]
)
def deactivate_account(
	payload: DeactivateAccountRequest,
	user: User = Depends(get_current_user),
	db: Session = Depends(get_db)
) -> SuccessResponse[None]:
	if not verify_password(user.password_hash, payload.password):
		raise AuthenticationException(
			message="Invalid password."
		)

	if user.status == UserStatus.DEACTIVATED:
		raise AccountDeactivatedException(
			message="Your account is already deactivated.",
		)
	
	db.execute(update(TokenFamily).where(TokenFamily.user_id == user.uid, TokenFamily.revoked_at.is_(None)).values(revoked_at=datetime.now(timezone.utc)))

	user.deleted_at = datetime.now(timezone.utc)
	user.status = UserStatus.DEACTIVATED
	
	return SuccessResponse[None](
		message="User deactivated successfully."
	)


@router.post(
	"/change-password",
	status_code=HTTPStatus.OK,
	response_model=SuccessResponse[None]
)
def change_password(
	payload: ChangePasswordRequest,
	user: User = Depends(get_current_user),
	db: Session = Depends(get_db)
) -> SuccessResponse[None]:
	if not verify_password(user.password_hash, payload.old_password):
		raise AuthenticationException(
			message="Invalid password."
		)
	
	user.password_hash = hash_password(payload.new_password)
	
	return SuccessResponse[None](
		message="Password changed successfully."
	)


@router.post(
	"/verify-mail",
	status_code=HTTPStatus.OK,
	response_model=SuccessResponse[None]
)
def mail_verification(
	payload: VerifyMailRequest,
	db: Session = Depends(get_db)
) -> SuccessResponse[None]:
	mail_verification_token = db.scalar(select(MailVerificationToken).where(MailVerificationToken.token_hash == token_services.hash_token(payload.token)))
	
	if mail_verification_token is None:
		raise BadRequestException(
			message="The verification token is invalid or malformed."
		)
	
	if mail_verification_token.expires_at <= datetime.now(timezone.utc):
		raise BadRequestException(
			message= "The verification token has expired. Please request a new one."
		)
	
	user = db.scalar(select(User).where(User.uid == mail_verification_token.user_id))
	if user is None:
		raise AppException()
	
	user.verified_at = datetime.now(timezone.utc)
	
	return SuccessResponse[None](
		message="Email verified successfully. You can now log in."
	)
	


@router.post(
	"/resend-verification",
	status_code=HTTPStatus.OK,
	response_model=SuccessResponse[None]
)
def resend_verification(
	payload: ResendVerificationMailRequest,
	request: Request,
	background_tasks: BackgroundTasks,
	db: Session = Depends(get_db)
) -> SuccessResponse[None]:
	user = db.scalar(select(User).where(User.email == payload.email))
	if user is None:
		return SuccessResponse[None](
	        message="If an account with this email exists, a verification email has been sent."
	    ) 
	
	raw_token, mail_verification_token = token_services.create_mail_verification_token(
		user.uid,
		request.headers.get("user-agent"),
		request.client.host if request.client else None,
	)
	
	db.add(mail_verification_token)
	
	# mail_services.send_verification_mail(payload.email, f"{settings.FRONTEND_URL}/mail-verification?token={raw_token}")
	background_tasks.add_task(mail_services.send_verification_mail, payload.email, f"{settings.FRONTEND_URL}/mail-verification?token={raw_token}")
	

	return SuccessResponse[None](
		message="If an account with this email exists, a verification email has been sent."
	)


@router.post(
	"/forgot-password",
	status_code=HTTPStatus.OK,
	response_model=SuccessResponse[None]
)
def forgot_password(
	payload: ForgotPasswordRequest,
	request: Request,
	background_tasks: BackgroundTasks,
	db: Session = Depends(get_db)
) -> SuccessResponse[None]:
	user = db.scalar(select(User).where(User.email == payload.email))
	if user is None:
		return SuccessResponse[None](
	        message="If an account with this email exists, a reset password email has been sent."
	    )
	
	raw_token, password_reset_token = token_services.create_password_reset_token(
		user.uid,
		request.headers.get("user-agent"),
		request.client.host if request.client else None,
	)
	
	db.add(password_reset_token)
	
	# mail_services.send_password_reset_mail(payload.email, f"{settings.FRONTEND_URL}/reset-password?token={raw_token}")
	background_tasks.add_task(mail_services.send_password_reset_mail, payload.email, f"{settings.FRONTEND_URL}/reset-password?token={raw_token}")

	return SuccessResponse[None](
		message="If an account with this email exists, a reset password email has been sent."
	)


@router.post(
	"/reset-password",
	status_code=HTTPStatus.OK,
	response_model=SuccessResponse[None]
)
def reset_password(
	payload: ResetPasswordRequest,
	db: Session = Depends(get_db)
) -> SuccessResponse[None]:
	password_reset_token = db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash == token_services.hash_token(payload.token)))
	
	if password_reset_token is None:
		raise BadRequestException(
			message="The password reset token is invalid or malformed."
		)
	
	if password_reset_token.expires_at <= datetime.now(timezone.utc):
		raise BadRequestException(
			message= "The password reset token has expired. Please request a new one."
		)
	
	user = db.scalar(select(User).where(User.uid == password_reset_token.user_id))
	if user is None:
		raise AppException()
	
	user.password_hash = hash_password(payload.password)
	
	db.execute(update(TokenFamily).where(TokenFamily.user_id == user.uid, TokenFamily.revoked_at.is_(None)).values(revoked_at=datetime.now(timezone.utc)))

	return SuccessResponse[None](
		message="Your password has been reset successfully. You can now log in with your new password."
	)


