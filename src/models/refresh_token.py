


from datetime import datetime
from typing import Union
import uuid

from sqlalchemy import UUID, Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column
from src.models.base import Base
from src.models.mixins.id import IDMixin
from src.models.mixins.timestamp import TimestampMixin


class RefreshToken(IDMixin, TimestampMixin, Base):
	__tablename__ = "refresh_tokens"
	
	family_id: Mapped[uuid.UUID] = mapped_column(
		UUID(as_uuid=True),
		nullable=False,
		index=True
	)
	
	user_id: Mapped[uuid.UUID] = mapped_column(
		UUID(as_uuid=True),
		ForeignKey("users.uid", ondelete="CASCADE"),
		nullable=False,
		index=True
	)
	
	token_hash: Mapped[str] = mapped_column(
		String(255),
		nullable=False,
		unique=True
	)
	
	expires_at: Mapped[datetime] = mapped_column(
		DateTime(timezone=True),
		nullable=False,
	)
	
	is_used: Mapped[bool] = mapped_column(
		Boolean,
		nullable=False,
		default=False,
		server_default="false"
	)
	
	device_info: Mapped[Union[str, None]] = mapped_column(
		String(255),
		nullable=True
	)



