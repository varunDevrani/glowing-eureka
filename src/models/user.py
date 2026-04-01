


from datetime import datetime
from typing import Union
from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column
from src.core.enums import UserRole, UserStatus
from src.models.base import Base
from src.models.mixins.id import IDMixin
from src.models.mixins.timestamp import TimestampMixin
from sqlalchemy import Enum



class User(IDMixin, TimestampMixin, Base):
	__tablename__ = "users"

	first_name: Mapped[Union[str, None]] = mapped_column(
		String(100),
		nullable=True
	)
	
	last_name: Mapped[Union[str, None]] = mapped_column(
		String(100),
		nullable=True
	)
	
	role: Mapped[UserRole] = mapped_column(
		Enum(UserRole),
		nullable=False,
		default=UserRole.USER
	)
	
	email: Mapped[str] = mapped_column(
		String(320),
		nullable=False,
		unique=True,
		index=True
	)
	
	password_hash: Mapped[str] = mapped_column(
		String(255),
		nullable=False
	)
	
	profile_pic_url: Mapped[Union[str, None]] = mapped_column(
		String(2048),
		nullable=True,
	)
	
	is_verified: Mapped[bool] = mapped_column(
		Boolean,
		nullable=False,
		default=False,
		server_default="false",
	)
	
	status: Mapped[UserStatus] = mapped_column(
		Enum(UserStatus),
		nullable=False,
		default=UserStatus.ACTIVE
	)
	
	deleted_at: Mapped[Union[datetime, None]] = mapped_column(
		DateTime(timezone=True),
		nullable=True
	)

