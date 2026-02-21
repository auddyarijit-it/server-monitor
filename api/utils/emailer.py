import time
import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from urllib.parse import urlparse

from config.settings import EMAIL, EMAIL_CRED_FILE


def clean_url(url):
    parsed = urlparse(url)
    return parsed.netloc


def load_creds():
    creds = {}
    with open(EMAIL_CRED_FILE) as f:
        for line in f:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                creds[k] = v
    return creds


# -----------------------------------------
# SERVER MONITOR ALERT EMAIL
# -----------------------------------------
def send_server_alert(server_name, alert_type, message):
    creds = load_creds()

    subject = f"[CRITICAL] {alert_type} Alert - {server_name}"

    msg = MIMEMultipart("related")
    msg["From"] = EMAIL["sender"]
    msg["To"] = EMAIL["receiver"]
    msg["Subject"] = subject

    msg_alternative = MIMEMultipart("alternative")
    msg.attach(msg_alternative)

    html = f"""
    <html>
    <body style="margin:0;padding:0;background-color:#f8fafc;font-family:Arial,sans-serif;">
        <div style="max-width:600px;margin:20px auto;background-color:#ffffff;
                    border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;">
            <div style="background-color:#ced9eb;padding:20px;text-align:center;">
                <img src="cid:techsum_logo" alt="TechSum" style="width:150px;">
            </div>
            <div style="padding:30px;">
                <h2 style="color:#1e293b;margin-top:0;">Server Alert</h2>
                <table cellpadding="10" style="width:100%;">
                    <tr><td><b>Server</b></td><td align="right">{server_name}</td></tr>
                    <tr><td><b>Alert</b></td><td align="right" style="color:#ef4444;"><b>{alert_type}</b></td></tr>
                    <tr><td><b>Message</b></td><td align="right">{message}</td></tr>
                    <tr><td><b>Time</b></td><td align="right">{time.strftime('%d-%b-%Y %H:%M:%S')} IST</td></tr>
                </table>
            </div>
        </div>
    </body>
    </html>
    """

    msg_alternative.attach(MIMEText(html, "html"))

    # Attach logo (optional)
    try:
        logo_path = os.path.join(os.path.dirname(__file__), "TechSum_logo.png")
        if os.path.exists(logo_path):
            with open(logo_path, "rb") as f:
                img = MIMEImage(f.read())
                img.add_header("Content-ID", "<techsum_logo>")
                img.add_header("Content-Disposition", "inline", filename="TechSum_logo.png")
                msg.attach(img)
    except Exception:
        pass

    with smtplib.SMTP(EMAIL["smtp_server"], EMAIL["smtp_port"]) as s:
        s.starttls()
        s.login(creds["AWS_SMTP_USERNAME"], creds["AWS_SMTP_PASSWORD"])
        s.send_message(msg)


# -----------------------------------------
# PASSWORD RESET EMAIL
# -----------------------------------------
def send_password_reset_email(user_email, reset_link):
    creds = load_creds()

    msg = MIMEMultipart("related")
    msg["From"] = EMAIL["sender"]
    msg["To"] = user_email
    msg["Subject"] = "Reset your TechSum Monitor password"

    msg_alternative = MIMEMultipart("alternative")
    msg.attach(msg_alternative)

    html = f"""
    <html>
    <body style="background:#f2f4f7;font-family:Arial,sans-serif;">
        <div style="max-width:500px;margin:40px auto;background:#ffffff;
                    border-radius:12px;overflow:hidden;">
            <div style="background:#1e293b;padding:20px;text-align:center;">
                <img src="cid:techsum_logo" style="width:140px;">
            </div>
            <div style="padding:30px;text-align:center;">
                <h2>Password Reset</h2>
                <p>This link will expire in <b>30 minutes</b>.</p>
                <a href="{reset_link}" style="
                    display:inline-block;
                    padding:12px 24px;
                    background:#4f46e5;
                    color:#fff;
                    text-decoration:none;
                    border-radius:8px;
                    font-weight:bold;
                ">Reset Password</a>
            </div>
        </div>
    </body>
    </html>
    """

    msg_alternative.attach(MIMEText(html, "html"))

    # Attach logo
    try:
        logo_path = os.path.join(os.path.dirname(__file__), "TechSum_logo.png")
        if os.path.exists(logo_path):
            with open(logo_path, "rb") as f:
                img = MIMEImage(f.read())
                img.add_header("Content-ID", "<techsum_logo>")
                img.add_header("Content-Disposition", "inline", filename="TechSum_logo.png")
                msg.attach(img)
    except Exception:
        pass

    with smtplib.SMTP(EMAIL["smtp_server"], EMAIL["smtp_port"]) as s:
        s.starttls()
        s.login(creds["AWS_SMTP_USERNAME"], creds["AWS_SMTP_PASSWORD"])
        s.send_message(msg)
