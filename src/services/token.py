from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from uuid import UUID
from typing import Union

from src.core.config import settings
from src.models.mail_verification_token import MailVerificationToken
from src.models.password_reset_token import PasswordResetToken
from src.models.refresh_token import RefreshToken
from src.services.external.geolocation import resolve_ip_location
from src.utils.jwt_handler import create_access_token



def create_opaque_token() -> str:
	return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
	return hashlib.sha256(token.encode()).hexdigest()


def create_auth_tokens(
	user_id: UUID,
	family_id: UUID,
	user_agent: Union[str, None] = None,
	ip_addr: Union[str, None] = None
) -> tuple[str, str, RefreshToken]:
	access_token = create_access_token(user_id)
	raw_refresh_token = create_opaque_token()
	
			
	refresh_token = RefreshToken(
		family_id=family_id,
		token_hash=hash_token(raw_refresh_token),
		expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
		user_agent=user_agent,
		ip_address=ip_addr,
		location=resolve_ip_location(ip_addr) if ip_addr else None
	)
	
	return (access_token, raw_refresh_token, refresh_token)


def create_mail_verification_token(
	user_id: UUID,
	user_agent: Union[str, None] = None,
	ip_addr: Union[str, None] = None
) -> tuple[str, MailVerificationToken]:
	raw_token = create_opaque_token()
	
	mail_verification_token = MailVerificationToken(
		user_id=user_id,
		token_hash=hash_token(raw_token),
		expires_at=datetime.now(timezone.utc) + timedelta(days=settings.MAIL_VERIFICATION_EXPIRY_DAYS),
		user_agent=user_agent,
		ip_address=ip_addr,
		location=resolve_ip_location(ip_addr) if ip_addr else None
	)
	
	return (raw_token, mail_verification_token)


def create_password_reset_token(
	user_id: UUID,
	user_agent: Union[str, None] = None,
	ip_addr: Union[str, None] = None
) -> tuple[str, PasswordResetToken]:
	raw_token = create_opaque_token()
	
	password_reset_token = PasswordResetToken(
		user_id=user_id,
		token_hash=hash_token(raw_token),
		expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.PASSWORD_RESET_EXPIRY_MINUTES),
		user_agent=user_agent,
		ip_address=ip_addr,
		location=resolve_ip_location(ip_addr) if ip_addr else None
	)
	
	return (raw_token, password_reset_token)


