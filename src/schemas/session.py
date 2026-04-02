


from datetime import datetime
from typing import Union
from uuid import UUID
from src.schemas.base import BaseSchema


class SessionResponse(BaseSchema):
	family_id: UUID
	device_info: Union[str, None] = None
	ip_address: Union[str, None] = None
	location: Union[str, None] = None
	created_at: datetime
	expires_at: datetime
	# is_current: bool


class SessionsResponse(BaseSchema):
	sessions: list[SessionResponse]

