

from http import HTTPStatus
from typing import Union
from src.errors.codes import ErrorCode


class AppException(Exception):
	def __init__(
		self,
		status_code: HTTPStatus = HTTPStatus.INTERNAL_SERVER_ERROR,
		error_code: ErrorCode = ErrorCode.INTERNAL_SERVER_ERROR,
		message: str = "Request execution failed.",
		extra: Union[dict, None] = None
	) -> None:
		self.status_code = status_code
		self.error_code = error_code
		self.message = message
		self.extra = extra or {}

		super().__init__(message)


class ConflictException(AppException):
	def __init__(
		self, 
		message: str = "The request conflicts with current state.", 
	) -> None:
		super().__init__(
			status_code=HTTPStatus.CONFLICT,
			error_code=ErrorCode.CONFLICT_ERROR,
			message=message
		)


class NotFoundException(AppException):
	def __init__(
		self,
		message: str = "The requested resource does not exist."
	) -> None:
		super().__init__(
			status_code=HTTPStatus.NOT_FOUND,
			error_code=ErrorCode.NOT_FOUND,
			message=message
		)


class AuthenticationException(AppException):
	def __init__(
		self,
		message: str = "Valid authentication credentials are required."
	) -> None:
		super().__init__(
			status_code=HTTPStatus.UNAUTHORIZED,
			error_code=ErrorCode.UNAUTHORIZED,
			message=message
		)


class AuthorizationException(AppException):
	def __init__(
		self,
		message: str = "You do not have permission to perform this action."
	) -> None:
		super().__init__(
			status_code=HTTPStatus.FORBIDDEN,
			error_code=ErrorCode.FORBIDDEN,
			message=message
		)


class BadRequestException(AppException):
	def __init__(
		self,
		message: str = "Bad request. The server could not process the request due to client error."
	) -> None:
		super().__init__(
			status_code=HTTPStatus.BAD_REQUEST,
			error_code=ErrorCode.BAD_REQUEST,
			message=message
		)


class AccountDeactivatedException(AppException):
	def __init__(
		self, 
		recoverable: bool = True,
		message: str ="Your account is deactivated. Would you like to reactivate it?"
	):
		super().__init__(
			status_code=HTTPStatus.LOCKED,
			error_code=ErrorCode.LOCKED,
			message=message,
			extra = {
				"recoverable": recoverable
			}
		)