"""Async email sender for scheduled reports.

Uses aiosmtplib (optional dependency). Falls back silently if SMTP is
not configured or aiosmtplib is not installed.
"""

from __future__ import annotations

from netlanventory.core.logging import get_logger

logger = get_logger(__name__)

try:
    import aiosmtplib  # type: ignore[import]
    _smtp_available = True
except ImportError:
    aiosmtplib = None  # type: ignore[assignment]
    _smtp_available = False


async def send_report_email(
    recipients: list[str],
    subject: str,
    html_body: str,
    pdf_attachment: bytes | None = None,
    attachment_name: str = "report.pdf",
) -> bool:
    """Send an HTML email with an optional PDF attachment.

    Returns True on success, False on failure or if SMTP is not configured.
    """
    if not _smtp_available:
        logger.warning("aiosmtplib not installed — email not sent", subject=subject)
        return False

    from netlanventory.core.config import get_settings
    settings = get_settings()

    if not settings.smtp_host:
        logger.debug("SMTP_HOST not configured — email skipped", subject=subject)
        return False

    if not recipients:
        return False

    import email.mime.application as app_mime
    import email.mime.multipart as multi_mime
    import email.mime.text as text_mime

    msg = multi_mime.MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = ", ".join(recipients)

    # HTML body
    html_part = text_mime.MIMEText(html_body, "html", "utf-8")
    msg.attach(html_part)

    # PDF attachment
    if pdf_attachment:
        pdf_part = app_mime.MIMEApplication(pdf_attachment, Name=attachment_name)
        pdf_part["Content-Disposition"] = f'attachment; filename="{attachment_name}"'
        msg.attach(pdf_part)

    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user or None,
            password=settings.smtp_password or None,
            use_tls=settings.smtp_tls,
            timeout=30,
        )
        logger.info(
            "Email sent",
            subject=subject,
            recipients=recipients,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("Email send failed", subject=subject, error=str(exc))
        return False
