
from typing import Union

from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.orm import Session
from src.core.enums import UserStatus
from src.deps.database import get_db
from src.errors.app_exception import AccountDeactivatedException, AuthenticationException
from src.models.token_family import TokenFamily
from src.models.user import User
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.utils.jwt_handler import decode_access_token


http_bearer = HTTPBearer(auto_error=False)

def get_current_user(
	credentials: Union[HTTPAuthorizationCredentials, None] = Depends(http_bearer),
	db: Session = Depends(get_db)
) -> User:
	
	if credentials is None:
		raise AuthenticationException(
			message="Authentication credentials were not provided."
		)
	
	
	payload = decode_access_token(credentials.credentials)
	
	token_family = db.scalar(select(TokenFamily).where(TokenFamily.uid == payload.sid))
	if token_family is None:
		raise AuthenticationException(
			message="Invalid token family provided."
		)

	if token_family.revoked_at is not None:
		raise AuthenticationException(
			message="Session ended. Please login again."
		)
	
	user = db.scalar(select(User).where(User.uid == payload.sub))
	if user is None:
		raise AuthenticationException(
			message="User associated with this token does not exist."
		)

	if user.status == UserStatus.DEACTIVATED:
		raise AccountDeactivatedException()
	
	return user

