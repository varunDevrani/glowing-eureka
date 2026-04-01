


import uuid
from sqlalchemy import UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import text


class IDMixin:
	uid: Mapped[uuid.UUID] = mapped_column(
		UUID(as_uuid=True),
		primary_key=True,
		default=uuid.uuid4,
		server_default=text("gen_random_uuid()")
	)
