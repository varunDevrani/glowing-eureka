


from datetime import datetime
from typing import Union
from uuid import UUID
from src.schemas.base import BaseSchema


class SessionResponse(BaseSchema):
	family_id: UUID
	user_agent: Union[str, None] = None
	ip_address: Union[str, None] = None
	location: Union[str, None] = None
	created_at: datetime
	expires_at: datetime
	current: bool = False


class SessionsResponse(BaseSchema):
	sessions: list[SessionResponse]

