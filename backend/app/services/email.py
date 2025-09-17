"""
Email service abstraction so providers can be swapped (SMTP, SendGrid, SES).
Current implementation logs to console; replace `ConsoleEmailProvider` with a real provider.
"""
from typing import Protocol


class EmailProvider(Protocol):
    def send(self, *, to: str, subject: str, html: str) -> None: ...


class ConsoleEmailProvider:
    def send(self, *, to: str, subject: str, html: str) -> None:
        print(f"[EMAIL] to={to} subject={subject}\n{html}")


provider: EmailProvider = ConsoleEmailProvider()


def send_password_reset_email(to_email: str, reset_link: str) -> None:
    subject = "Reset your password"
    html = f"""
    <h2>Password Reset</h2>
    <p>We received a request to reset your password.</p>
    <p><a href=\"{reset_link}\">Click here to reset your password</a></p>
    <p>If you did not request this, you can ignore this email.</p>
    """
    provider.send(to=to_email, subject=subject, html=html)


