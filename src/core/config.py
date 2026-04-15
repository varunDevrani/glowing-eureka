


from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
	DATABASE_URL: SecretStr
	
	JWT_ALGORITHM: str
	JWT_SECRET_KEY: SecretStr
	ACCESS_TOKEN_EXPIRE_MINUTES: int
	REFRESH_TOKEN_EXPIRE_DAYS: int
	
	MAIL_HOST: str
	MAIL_PORT: int
	MAIL_USER: SecretStr
	MAIL_PASS: SecretStr
	MAIL_VERIFICATION_EXPIRY_DAYS: int
	
	PASSWORD_RESET_EXPIRY_MINUTES:int 
	
	FRONTEND_URL: str
			
	model_config = SettingsConfigDict(
		strict=True,
		extra="forbid",
		validate_assignment=True,
		validate_default=True,
		case_sensitive=True,
		env_file=".env"
	)




settings = Settings() # type: ignore
