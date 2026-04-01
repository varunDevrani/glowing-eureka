


from pydantic import BaseModel, ConfigDict


class BaseSchema(BaseModel):
	model_config = ConfigDict(
		extra="forbid",
		validate_assignment=True,
		strict=True,
		validate_default=True,
		validate_return=True,
		from_attributes=True,
	)
