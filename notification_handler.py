"""
Notification handler for email alerts and desktop notifications.

Provides email delivery (SMTP) and Windows 10 Toast notifications
for system and security alerts triggered by the monitoring agent.
"""

from __future__ import annotations

import logging
import smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional, Set, Tuple

import config

logger = logging.getLogger(__name__)

try:
    from win10toast import ToastNotifier
    TOAST_AVAILABLE = True
except ImportError:
    TOAST_AVAILABLE = False
    logger.warning("win10toast not installed; desktop notifications will be disabled")


class NotificationHandler:
    """Manages email and desktop notifications for alerts."""

    def __init__(self) -> None:
        """Initialize notification handler with rate limiting and batching."""
        self.email_enabled = config.EMAIL_NOTIFICATIONS_ENABLED
        self.desktop_enabled = config.DESKTOP_NOTIFICATION_ENABLED and TOAST_AVAILABLE
        self.toaster: Optional[ToastNotifier] = None

        # Rate limiting tracking (alert_type -> last_sent_timestamp)
        self._rate_limit_cache: Dict[str, datetime] = {}
        
        # Email batching
        self._batched_alerts: List[Dict[str, Any]] = []
        self._last_batch_sent: Optional[datetime] = None
        self._batching_enabled = config.EMAIL_BATCH_ALERTS

        # Severity threshold tracking
        self._notification_severity_order = {
            config.SEVERITY_CRITICAL: 0,
            config.SEVERITY_HIGH: 1,
            config.SEVERITY_MEDIUM: 2,
            config.SEVERITY_LOW: 3,
            config.SEVERITY_INFO: 4,
        }

        # Validate email configuration
        if self.email_enabled:
            self._validate_email_config()

        # Initialize desktop notification
        if self.desktop_enabled:
            try:
                self.toaster = ToastNotifier()
                logger.info("Desktop notifications initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize desktop notifications: {e}")
                self.desktop_enabled = False

        logger.info(f"NotificationHandler initialized (email={self.email_enabled}, desktop={self.desktop_enabled})")

    def _validate_email_config(self) -> None:
        """Validate email configuration."""
        if not config.EMAIL_SENDER:
            logger.warning("EMAIL_SENDER not configured; email notifications disabled")
            self.email_enabled = False
        elif not config.EMAIL_RECIPIENTS:
            logger.warning("EMAIL_RECIPIENTS not configured; email notifications disabled")
            self.email_enabled = False
        elif not config.EMAIL_SENDER_PASSWORD:
            logger.warning("EMAIL_SENDER_PASSWORD not configured; email notifications disabled")
            self.email_enabled = False

    def _should_notify(self, alert: Dict[str, Any], alert_type: str) -> bool:
        """Check if alert should trigger a notification based on severity and rate limiting."""
        severity = alert.get("severity", config.SEVERITY_INFO)
        
        # Check severity threshold
        if not self._is_severity_sufficient(severity, config.NOTIFICATION_SEVERITY_THRESHOLD):
            return False

        # Check alert type trigger configuration
        if not self._is_alert_type_enabled(alert_type):
            return False

        # Check rate limiting
        if not self._check_rate_limit(alert_type):
            return False

        return True

    def _is_severity_sufficient(self, severity: str, threshold: str) -> bool:
        """Check if alert severity meets or exceeds threshold."""
        severity_level = self._notification_severity_order.get(severity, 99)
        threshold_level = self._notification_severity_order.get(threshold, 99)
        return severity_level <= threshold_level

    def _is_alert_type_enabled(self, alert_type: str) -> bool:
        """Check if alert type is enabled for notifications."""
        alert_type_lower = alert_type.lower()
        
        if "suspicious" in alert_type_lower or "injection" in alert_type_lower or "masquer" in alert_type_lower:
            return config.ALERT_TRIGGER_SUSPICIOUS_PROCESS
        
        if "threshold" in alert_type_lower or "spike" in alert_type_lower or "leak" in alert_type_lower:
            return config.ALERT_TRIGGER_SYSTEM_THRESHOLD
        
        if "injection" in alert_type_lower or "code cave" in alert_type_lower or "hollow" in alert_type_lower:
            return config.ALERT_TRIGGER_INJECTION_DETECTED
        
        if "service" in alert_type_lower:
            return config.ALERT_TRIGGER_UNUSUAL_SERVICE
        
        return True  # Default to enabled if type not matched

    def _check_rate_limit(self, alert_type: str) -> bool:
        """Check if alert type should be rate-limited."""
        if not config.RATE_LIMIT_ENABLED:
            return True

        last_sent = self._rate_limit_cache.get(alert_type)
        if last_sent is None:
            self._rate_limit_cache[alert_type] = datetime.now()
            return True

        elapsed = (datetime.now() - last_sent).total_seconds()
        if elapsed >= config.RATE_LIMIT_SECONDS:
            self._rate_limit_cache[alert_type] = datetime.now()
            return True

        logger.debug(
            f"Rate limit applied to {alert_type} ({elapsed:.1f}s < {config.RATE_LIMIT_SECONDS}s)"
        )
        return False

    def send_desktop_notification(
        self,
        title: str,
        message: str,
        severity: str = config.SEVERITY_INFO,
    ) -> bool:
        """Send a Windows 10 Toast notification."""
        if not self.desktop_enabled or self.toaster is None:
            return False

        try:
            # Truncate message if too long
            max_length = 256
            if len(message) > max_length:
                message = message[: max_length - 3] + "..."

            self.toaster.show_toast(
                title=title,
                msg=message,
                duration=config.NOTIFICATION_TOAST_DURATION,
                threaded=True,
            )
            logger.info(f"Desktop notification sent: {title}")
            return True
        except Exception as e:
            logger.error(f"Failed to send desktop notification: {e}")
            return False

    def _format_alert_for_email(self, alert: Dict[str, Any]) -> str:
        """Format a single alert for email body."""
        severity = alert.get("severity", config.SEVERITY_INFO)
        alert_type = alert.get("type", "Unknown")
        timestamp = alert.get("timestamp", datetime.now())
        reason = alert.get("reason") or alert.get("description", "N/A")
        risk_score = alert.get("risk_score", "N/A")

        formatted = f"""
{'=' * 70}
Alert Type:    {alert_type}
Severity:      {severity}
Risk Score:    {risk_score}
Timestamp:     {timestamp}
Reason:        {reason}

Additional Details:
"""
        # Add custom fields
        standard_fields = {"type", "severity", "timestamp", "description", "reason", "risk_score"}
        for key in sorted(alert.keys()):
            if key not in standard_fields:
                formatted += f"  {key.replace('_', ' ').title()}: {alert[key]}\n"

        return formatted

    def send_email_alert(
        self,
        alert: Dict[str, Any],
        subject_prefix: str = "[SECURITY ALERT]",
    ) -> bool:
        """Send an email alert."""
        if not self.email_enabled:
            return False

        if not config.EMAIL_RECIPIENTS:
            logger.warning("No email recipients configured")
            return False

        try:
            severity = alert.get("severity", config.SEVERITY_INFO)
            alert_type = alert.get("type", "Unknown")
            risk_score = alert.get("risk_score", "N/A")

            # Build email
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"{subject_prefix} {severity} - {alert_type} (Risk: {risk_score})"
            msg["From"] = config.EMAIL_SENDER
            msg["To"] = ", ".join(config.EMAIL_RECIPIENTS)
            msg["X-Alert-Type"] = alert_type
            msg["X-Severity"] = severity

            # Plain text body
            text_body = self._format_alert_for_email(alert)
            part1 = MIMEText(text_body, "plain")
            msg.attach(part1)

            # HTML body (for better formatting)
            html_body = f"""
<html>
  <body style="font-family: Arial, sans-serif;">
    <div style="background-color: #f5f5f5; padding: 20px; border-radius: 5px;">
      <h2 style="color: #d9534f;">🚨 Security Alert</h2>
      <table style="width: 100%; border-collapse: collapse;">
        <tr style="background-color: #e8e8e8;">
          <td style="padding: 10px; font-weight: bold; width: 150px;">Alert Type:</td>
          <td style="padding: 10px;">{alert_type}</td>
        </tr>
        <tr>
          <td style="padding: 10px; font-weight: bold;">Severity:</td>
          <td style="padding: 10px; color: #d9534f;"><strong>{severity}</strong></td>
        </tr>
        <tr style="background-color: #e8e8e8;">
          <td style="padding: 10px; font-weight: bold;">Risk Score:</td>
          <td style="padding: 10px;">{risk_score}</td>
        </tr>
        <tr>
          <td style="padding: 10px; font-weight: bold;">Timestamp:</td>
          <td style="padding: 10px;">{alert.get('timestamp', datetime.now())}</td>
        </tr>
        <tr style="background-color: #e8e8e8;">
          <td style="padding: 10px; font-weight: bold;">Reason:</td>
          <td style="padding: 10px;">{alert.get('reason') or alert.get('description', 'N/A')}</td>
        </tr>
      </table>
      <hr style="margin: 20px 0; border: 1px solid #ddd;">
      <h3>Additional Details:</h3>
      <ul>
"""
            standard_fields = {"type", "severity", "timestamp", "description", "reason", "risk_score"}
            for key in sorted(alert.keys()):
                if key not in standard_fields:
                    html_body += f"        <li><strong>{key.replace('_', ' ').title()}:</strong> {alert[key]}</li>\n"

            html_body += """
      </ul>
      <hr style="margin: 20px 0; border: 1px solid #ddd;">
      <p style="color: #666; font-size: 12px;">
        This alert was generated by the Windows Service & Process Monitoring Agent.
        Please review the system immediately to determine if further action is required.
      </p>
    </div>
  </body>
</html>
"""
            part2 = MIMEText(html_body, "html")
            msg.attach(part2)

            # Send email
            with smtplib.SMTP(config.EMAIL_SMTP_SERVER, config.EMAIL_SMTP_PORT) as server:
                if config.EMAIL_USE_TLS:
                    server.starttls()
                server.login(config.EMAIL_SENDER, config.EMAIL_SENDER_PASSWORD)
                server.sendmail(config.EMAIL_SENDER, list(config.EMAIL_RECIPIENTS), msg.as_string())

            logger.info(f"Email alert sent to {len(config.EMAIL_RECIPIENTS)} recipient(s): {alert_type}")
            return True

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"Email authentication failed: {e}")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error while sending alert: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending email alert: {e}", exc_info=True)
            return False

    def handle_alert(
        self,
        alert: Dict[str, Any],
        send_immediate: bool = False,
    ) -> bool:
        """Handle alert notifications (email and/or desktop)."""
        alert_type = alert.get("type", "Unknown")

        # Check if notification should be sent
        if not self._should_notify(alert, alert_type):
            logger.debug(f"Notification skipped for {alert_type} (threshold/rate limit/type not enabled)")
            return False

        notification_sent = False

        # Send desktop notification
        if self.desktop_enabled:
            severity = alert.get("severity", config.SEVERITY_INFO)
            reason = alert.get("reason") or alert.get("description", "No details")
            
            desktop_sent = self.send_desktop_notification(
                title=f"[{severity}] {alert_type}",
                message=reason,
                severity=severity,
            )
            notification_sent = notification_sent or desktop_sent

        # Handle email (batched or immediate)
        if self.email_enabled:
            if self._batching_enabled and not send_immediate:
                self._batched_alerts.append(alert)
                logger.debug(f"Alert batched for email: {alert_type} ({len(self._batched_alerts)} total)")
                notification_sent = True
            else:
                email_sent = self.send_email_alert(alert)
                notification_sent = notification_sent or email_sent

        return notification_sent

    def flush_batched_alerts(self) -> int:
        """Send all batched alerts in a single email."""
        if not self._batched_alerts or not self.email_enabled:
            return 0

        try:
            alert_count = len(self._batched_alerts)
            
            # Build combined email
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[SECURITY ALERTS] {alert_count} alert(s) from monitoring scan"
            msg["From"] = config.EMAIL_SENDER
            msg["To"] = ", ".join(config.EMAIL_RECIPIENTS)
            msg["X-Alert-Count"] = str(alert_count)

            # Plain text body
            text_body = f"Monitoring Scan Alert Summary\n{'=' * 70}\n\n"
            text_body += f"Total Alerts: {alert_count}\n\n"
            
            for alert in self._batched_alerts:
                text_body += self._format_alert_for_email(alert) + "\n"

            part1 = MIMEText(text_body, "plain")
            msg.attach(part1)

            # HTML body
            html_body = """
<html>
  <body style="font-family: Arial, sans-serif;">
    <div style="background-color: #f5f5f5; padding: 20px; border-radius: 5px;">
      <h2 style="color: #d9534f;">🚨 Monitoring Scan Summary</h2>
      <p>The following <strong>{}</strong> alert(s) were detected during the monitoring scan:</p>
      <hr style="margin: 20px 0; border: 1px solid #ddd;">
""".format(alert_count)

            severity_counts: Dict[str, int] = {}
            for alert in self._batched_alerts:
                severity = alert.get("severity", config.SEVERITY_INFO)
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            html_body += "<h3>Summary by Severity:</h3><ul>"
            for severity in sorted(severity_counts.keys()):
                html_body += f"<li><strong>{severity}:</strong> {severity_counts[severity]}</li>\n"
            html_body += "</ul><hr style='margin: 20px 0; border: 1px solid #ddd;'>"

            # Detailed alerts
            html_body += "<h3>Alert Details:</h3>"
            for i, alert in enumerate(self._batched_alerts, 1):
                alert_type = alert.get("type", "Unknown")
                severity = alert.get("severity", config.SEVERITY_INFO)
                risk_score = alert.get("risk_score", "N/A")
                timestamp = alert.get("timestamp", datetime.now())
                reason = alert.get("reason") or alert.get("description", "N/A")

                html_body += f"""
<div style="margin-bottom: 15px; padding: 10px; background-color: #fff; border-left: 4px solid #d9534f;">
  <h4 style="margin-top: 0;">{i}. {alert_type}</h4>
  <table style="width: 100%; font-size: 13px;">
    <tr><td style="width: 120px; font-weight: bold;">Severity:</td><td>{severity}</td></tr>
    <tr><td style="font-weight: bold;">Risk Score:</td><td>{risk_score}</td></tr>
    <tr><td style="font-weight: bold;">Timestamp:</td><td>{timestamp}</td></tr>
    <tr><td style="font-weight: bold;">Reason:</td><td>{reason}</td></tr>
  </table>
</div>
"""

            html_body += """
      <hr style="margin: 20px 0; border: 1px solid #ddd;">
      <p style="color: #666; font-size: 12px;">
        This summary was generated by the Windows Service & Process Monitoring Agent.
        Review each alert and take appropriate action as needed.
      </p>
    </div>
  </body>
</html>
"""
            part2 = MIMEText(html_body, "html")
            msg.attach(part2)

            # Send email
            with smtplib.SMTP(config.EMAIL_SMTP_SERVER, config.EMAIL_SMTP_PORT) as server:
                if config.EMAIL_USE_TLS:
                    server.starttls()
                server.login(config.EMAIL_SENDER, config.EMAIL_SENDER_PASSWORD)
                server.sendmail(config.EMAIL_SENDER, list(config.EMAIL_RECIPIENTS), msg.as_string())

            logger.info(f"Batched email sent with {alert_count} alert(s)")
            self._batched_alerts = []
            self._last_batch_sent = datetime.now()
            return alert_count

        except Exception as e:
            logger.error(f"Failed to send batched alerts: {e}", exc_info=True)
            return 0

    def should_flush_batch(self) -> bool:
        """Check if batched alerts should be flushed."""
        if not self._batched_alerts:
            return False

        if not self._batching_enabled:
            return False

        if self._last_batch_sent is None:
            elapsed = (datetime.now() - datetime.now()).total_seconds()
        else:
            elapsed = (datetime.now() - self._last_batch_sent).total_seconds()

        return elapsed >= config.EMAIL_BATCH_INTERVAL_SECONDS

    def get_notification_stats(self) -> Dict[str, Any]:
        """Get notification handler statistics."""
        return {
            "email_enabled": self.email_enabled,
            "desktop_enabled": self.desktop_enabled,
            "batched_alerts_pending": len(self._batched_alerts),
            "rate_limited_types": len(self._rate_limit_cache),
            "batching_enabled": self._batching_enabled,
            "last_batch_sent": self._last_batch_sent,
        }
