



from http import HTTPStatus
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from src.errors.app_exception import AppException
from src.errors.codes import ErrorCode


def register_exception_handlers(app: FastAPI):
	
	@app.exception_handler(AppException)
	def app_exception_handler(
		request: Request,
		exc: AppException
	) -> JSONResponse:
		return JSONResponse(
			status_code=exc.status_code,
			content={
				"success": False,
				"error_code": exc.error_code,
				"message": exc.message,
				**exc.extra
			}
		)
	
	
	@app.exception_handler(RequestValidationError)
	def validation_exception_handler(
		request: Request,
		exc: RequestValidationError
	) -> JSONResponse:
		return JSONResponse(
			status_code=HTTPStatus.UNPROCESSABLE_CONTENT,
			content={
				"success": False,
				"error_code": ErrorCode.UNPROCESSABLE_CONTENT,
				"message": "The request validation failed.",
				"errors": exc.errors()
			}
		)
	
	
	@app.exception_handler(Exception)
	def all_exception_handler(
		request: Request,
		exc: Exception
	) -> JSONResponse:
		#############################
		# TODO: Remove this
		# will implement logging later
		print()
		print(str(exc))
		print()
		#############################
		return JSONResponse(
			status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
			content={
				"success": False,
				"error_code": ErrorCode.INTERNAL_SERVER_ERROR,
				"message": "An unexpected error occurred."
			}
		)


