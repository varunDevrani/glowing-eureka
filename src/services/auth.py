


from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from uuid import UUID, uuid4
import requests
from typing import Union

from src.core.config import settings
from src.errors.app_exception import AuthenticationException
from src.models.refresh_token import RefreshToken
from src.models.user import User
from src.utils.hash import DUMMY_HASH, verify_password
from src.utils.jwt_handler import create_access_token



def authenticate_user_via_email(
	user: Union[User, None],
	passwd: str,
) -> User:
	if user is None:
		verify_password(DUMMY_HASH, passwd) # timing attacks
		raise AuthenticationException(
			message="Invalid email or password.",
		)
	
	if not verify_password(user.password_hash, passwd):
		raise AuthenticationException(
			message="Invalid email or password."
		)
	
	return user


def resolve_ip_location(ip_addr: str) -> Union[str, None]:
	try:
		ip_loc_response = requests.get(
			url=f"http://ip-api.com/json/{ip_addr}?fields=status,country,city",
			timeout=3
		)
		data = ip_loc_response.json()
		if data.get("status") == "success":
			return f"{data.get("city")}, {data.get("country")}"
		return None
	except Exception:
		return None


def hash_token(token: str) -> str:
	return hashlib.sha256(token.encode()).hexdigest()


def create_tokens(
	user: User,
	user_agent: Union[str, None],
	ip_addr: Union[str, None],
	family_id: Union[UUID, None] = None
) -> tuple[str, str, RefreshToken]:
	access_token = create_access_token(user.uid)
	raw_refresh_token = secrets.token_urlsafe(32)
	
	location = None
	if ip_addr:
		location = resolve_ip_location(ip_addr)
		
	refresh_token = RefreshToken(
		user_id=user.uid,
		family_id=family_id if family_id is not None else uuid4(),
		token_hash=hash_token(raw_refresh_token),
		expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
		device_info=user_agent,
		ip_address=ip_addr,
		location=location
	)
	
	return (access_token, raw_refresh_token, refresh_token)


