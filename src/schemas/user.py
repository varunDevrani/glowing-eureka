


from datetime import datetime
from typing import Annotated, Union
from uuid import UUID

from pydantic import BeforeValidator, EmailStr, Field, HttpUrl, field_validator
from src.core.enums import UserRole
from src.schemas.base import BaseSchema


Name = Annotated[
	str,
	Field(min_length=2, max_length=20),
	BeforeValidator(lambda value: value.strip())
]

class UserResponse(BaseSchema):
	uid: UUID
	first_name: Union[str, None] = None
	last_name: Union[str, None] = None
	role: UserRole
	email: EmailStr
	profile_pic_url: Union[HttpUrl, None] = None
	created_at: datetime
	updated_at: datetime


class UserUpdateRequest(BaseSchema):
	first_name: Union[Name, None] = None
	last_name: Union[Name, None] = None

	@field_validator("first_name", "last_name")
	def validate_names(cls, value: Union[str, None] = None) -> Union[str, None]:
		if value is not None:
			for char in "1234567890`~!@#$%^&*()-=_+[]\\{}|;':,./<?\" ":
				if char in value:
					raise ValueError("Names should not contain spaces, numbers or symbols.")
			return value.capitalize()
		return None

