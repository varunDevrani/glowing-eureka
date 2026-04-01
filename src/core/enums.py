

from enum import Enum


class UserRole(str, Enum):
	ADMIN = "admin"
	USER = "user"


class UserStatus(str, Enum):
	ACTIVE = "active"
	DEACTIVATED = "deactivated"
	BANNED = "banned"

