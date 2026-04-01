from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


password_hasher = PasswordHasher()


def hash_password(plain_passwd: str) -> str:
	return password_hasher.hash(plain_passwd)


def verify_password(hash_passwd: str, plain_passwd: str) -> bool:
	try:
		password_hasher.verify(hash_passwd, plain_passwd)
		return True
	except VerifyMismatchError:
		return False


DUMMY_HASH = hash_password("correct horse battery staple")
