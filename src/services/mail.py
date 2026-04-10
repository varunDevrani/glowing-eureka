import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from src.core.config import settings


def _send_mail(
	to_mail: str,
	subject: str,
	html_body: str
) -> None:
	msg = MIMEMultipart("alternative")
	msg["Subject"] = subject
	msg["From"] = settings.MAIL_USER.get_secret_value()
	msg["To"] = to_mail
	
	msg.attach(MIMEText(html_body, "html"))
	
	with smtplib.SMTP(settings.MAIL_HOST, settings.MAIL_PORT) as server:
		server.ehlo()
		server.starttls()
		server.ehlo()
		server.login(settings.MAIL_USER.get_secret_value(), settings.MAIL_PASS.get_secret_value())
		server.sendmail(settings.MAIL_HOST, to_mail, msg.as_string())



def send_verification_mail(
	to_mail: str,
	verification_link: str
) -> None:
	html_body = f"""
	<!DOCTYPE html>
	<html>
	<body>
			<h2>Welcome!</h2>
			<p>Verify your email:</p>
			<a href="{verification_link}">Verify Email</a>
			<p>This link expires in {settings.MAIL_VERIFICATION_EXPIRY_DAYS} day(s).</p>
	</body>
	</html>
	"""	
	_send_mail(to_mail, "Verify your email address.", html_body)


def send_password_reset_mail(
	to_mail: str,
	reset_link: str
) -> None:
	html_body = f"""
	<!DOCTYPE html>
	<html>
	<body>
			<h2>Password Reset</h2>
			<p>Reset your password:</p>
			<a href="{reset_link}">Reset Password</a>
			<p>This link expires in {settings.PASSWORD_RESET_EXPIRY_MINUTES} minutes.</p>
	</body>
	</html>
	"""
	_send_mail(to_mail, "Reset your password.", html_body)

