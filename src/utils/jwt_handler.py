from datetime import datetime, timedelta, timezone
from uuid import UUID
import jwt
from pydantic import BaseModel

from src.core.enums import UserRole
from src.core.config import settings
from src.errors.app_exception import AuthenticationException


ALGORITHM = "HS256"


class AccessTokenPayload(BaseModel):
	sub: UUID
	sid: UUID
	role: UserRole
	iat: int
	exp: int



def create_access_token(
	user_id: UUID,
	session_id: UUID,
	role: UserRole = UserRole.USER
) -> str:
	current_time = datetime.now(timezone.utc)
	expire_time = current_time + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
	
	payload = AccessTokenPayload(
		sub=user_id,
		sid=session_id,
		role=role,
		iat=int(current_time.timestamp()),
		exp=int(expire_time.timestamp())
	)
	
	return jwt.encode(payload.model_dump(mode="json"), settings.JWT_SECRET_KEY.get_secret_value(), ALGORITHM)


def decode_access_token(
	token: str
) -> AccessTokenPayload:
	try:
		raw_payload: dict = jwt.decode(token, settings.JWT_SECRET_KEY.get_secret_value(), [ALGORITHM])
		return AccessTokenPayload(**raw_payload)
	except jwt.ExpiredSignatureError:
		raise AuthenticationException(
			message="Provided JWT token has expired."
		)
	except jwt.InvalidTokenError:
		raise AuthenticationException(
			message="Provided JWT token is invalid."
		)

