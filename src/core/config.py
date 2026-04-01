


from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
	DATABASE_URL: SecretStr
	
	JWT_SECRET_KEY: SecretStr
	ACCESS_TOKEN_EXPIRE_MINUTES: int
	REFRESH_TOKEN_EXPIRE_DAYS: int
	
	MAX_SESSION_PER_USER: int
	
	model_config = SettingsConfigDict(
		strict=True,
		extra="forbid",
		validate_assignment=True,
		validate_default=True,
		case_sensitive=True,
		env_file=".env"
	)




settings = Settings() # type: ignore
