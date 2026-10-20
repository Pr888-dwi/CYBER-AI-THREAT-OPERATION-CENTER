import os
import smtplib
from email.message import EmailMessage

import requests


class AlertService:
    def __init__(self, smtp_host=None, smtp_port=587, smtp_user=None, smtp_password=None, telegram_bot_token=None, telegram_chat_id=None):
        self.smtp_host = smtp_host or os.getenv("SMTP_HOST")
        self.smtp_port = int(smtp_port or os.getenv("SMTP_PORT", 587))
        self.smtp_user = smtp_user or os.getenv("SMTP_USER")
        self.smtp_password = smtp_password or os.getenv("SMTP_PASSWORD")
        self.telegram_bot_token = telegram_bot_token or os.getenv("TELEGRAM_BOT_TOKEN")
        self.telegram_chat_id = telegram_chat_id or os.getenv("TELEGRAM_CHAT_ID")

    def send_email(self, subject, body):
        if not self.smtp_host or not self.smtp_user or not self.smtp_password:
            return False
        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = subject
        msg["From"] = self.smtp_user
        msg["To"] = self.smtp_user
        with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
            server.starttls()
            server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)
        return True

    def send_telegram(self, message):
        if not self.telegram_bot_token or not self.telegram_chat_id:
            return False
        url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
        response = requests.post(url, json={"chat_id": self.telegram_chat_id, "text": message}, timeout=10)
        return response.status_code == 200
