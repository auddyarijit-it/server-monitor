EMAIL_CRED_FILE = "/var/www/html/servermonitor.tsdemo.co.in/email_credentials"

EMAIL = {
    "smtp_server": "email-smtp.ap-south-1.amazonaws.com",
    "smtp_port": 587,
    "sender": "Server Usage Alert <uptime@techsumsolution.com>",
    "receiver": "server_monitor@techsumsolution.com",
    "logo_path": "/etc/script/ServerMonitor/TechSum.png",
}

CHECK = {
    "timeout": 10,
    "default_interval": 300,
}

