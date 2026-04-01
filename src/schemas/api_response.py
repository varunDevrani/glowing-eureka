from typing import Union
from src.schemas.base import BaseSchema


class SuccessResponse[T](BaseSchema):
	success: bool = True
	message: str = "Request execution successful."
	data: Union[T, None] = None

