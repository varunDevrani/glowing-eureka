from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID
import jwt

from src.core.enums import UserRole
from src.core.config import settings
from src.errors.app_exception import AuthenticationException


ALGORITHM = "HS256"


@dataclass
class AccessTokenPayload:
	sub: UUID
	admin: UserRole
	iat: int
	exp: int
	
	def to_dict(self) -> dict:
		return {
			"sub": str(self.sub),
			"admin": True if self.admin == UserRole.ADMIN else False,
			"iat": self.iat,
			"exp": self.exp
		}
	
	@classmethod
	def from_dict(cls, data: dict):
		return cls(
			sub=UUID(data["sub"]),
			admin=UserRole.ADMIN if data["admin"] else UserRole.USER,
			iat=data["iat"],
			exp=data["exp"]
		)



def create_access_token(
	user_id: UUID,
	role: UserRole = UserRole.USER
) -> str:
	current_time = datetime.now(timezone.utc)
	expire_time = current_time + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
	
	payload = AccessTokenPayload(
		sub=user_id,
		admin=role,
		iat=int(current_time.timestamp()),
		exp=int(expire_time.timestamp())
	)
	
	return jwt.encode(payload.to_dict(), settings.JWT_SECRET_KEY.get_secret_value(), ALGORITHM)


def decode_access_token(
	token: str
) -> AccessTokenPayload:
	try:
		raw_payload: dict = jwt.decode(token, settings.JWT_SECRET_KEY.get_secret_value(), [ALGORITHM])
		return AccessTokenPayload.from_dict(raw_payload)
	except jwt.ExpiredSignatureError:
		raise AuthenticationException(
			message="Provided JWT token has expired."
		)
	except jwt.InvalidTokenError:
		raise AuthenticationException(
			message="Provided JWT token is invalid."
		)

