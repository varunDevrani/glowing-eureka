

from http import HTTPStatus
from typing import Union
from src.errors.codes import ErrorCode


class AppException(Exception):
	def __init__(
		self,
		status_code: HTTPStatus = HTTPStatus.INTERNAL_SERVER_ERROR,
		error_code: ErrorCode = ErrorCode.INTERNAL_SERVER_ERROR,
		message: str = "Something went wrong. Please try again later.",
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
	 	error_code: ErrorCode = ErrorCode.CONFLICT_ERROR,
		message: str = "The request conflicts with current state.", 
	) -> None:
		super().__init__(
			status_code=HTTPStatus.CONFLICT,
			error_code=error_code,
			message=message
		)


class NotFoundException(AppException):
	def __init__(
		self,
		error_code: ErrorCode = ErrorCode.NOT_FOUND,
		message: str = "The requested resource does not exist."
	) -> None:
		super().__init__(
			status_code=HTTPStatus.NOT_FOUND,
			error_code=error_code,
			message=message
		)


class AuthenticationException(AppException):
	def __init__(
		self,
		error_code: ErrorCode = ErrorCode.UNAUTHORIZED,
		message: str = "Valid authentication credentials are required."
	) -> None:
		super().__init__(
			status_code=HTTPStatus.UNAUTHORIZED,
			error_code=error_code,
			message=message
		)


class AuthorizationException(AppException):
	def __init__(
		self,
		error_code: ErrorCode = ErrorCode.FORBIDDEN,
		message: str = "You do not have permission to perform this action."
	) -> None:
		super().__init__(
			status_code=HTTPStatus.FORBIDDEN,
			error_code=error_code,
			message=message
		)


class BadRequestException(AppException):
	def __init__(
		self,
		error_code: ErrorCode = ErrorCode.BAD_REQUEST,
		message: str = "Bad request. The server could not process the request due to client error."
	) -> None:
		super().__init__(
			status_code=HTTPStatus.BAD_REQUEST,
			error_code=error_code,
			message=message
		)


class AccountDeactivatedException(AppException):
	def __init__(
		self, 
		error_code: ErrorCode = ErrorCode.LOCKED,
		message: str ="Your account is deactivated. Would you like to reactivate it?",
		recoverable: bool = True
	):
		super().__init__(
			status_code=HTTPStatus.LOCKED,
			error_code=error_code,
			message=message,
			extra = {
				"recoverable": recoverable
			}
		)


