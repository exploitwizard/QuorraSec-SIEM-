# app/email_service.py — Resend-powered transactional email for Courra-Sec
import logging
from app.config import Config

logger = logging.getLogger(__name__)


# ── Low-level Resend wrapper ──────────────────────────────────────────────────

def _resend_send(to_email: str, subject: str, html: str) -> bool:
    """Send one email via Resend. Returns True on success, False otherwise."""
    if not Config.RESEND_API_KEY:
        return False
    try:
        import resend
        resend.api_key = Config.RESEND_API_KEY
        resend.Emails.send({
            "from":    Config.RESEND_FROM_EMAIL,
            "to":      [to_email],
            "subject": subject,
            "html":    html,
        })
        logger.info("Email sent to %s — %s", to_email, subject)
        return True
    except Exception as exc:
        logger.error("Resend error to %s: %s", to_email, exc)
        return False


# ── Shared HTML helpers (new-style: #0f1117 / #1a1f2e / #6366f1) ─────────────

def _email_html(body_html: str, login_url: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
</head>
<body style="margin:0;padding:0;background:#0f1117;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0f1117;padding:40px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0"
             style="background:#1a1f2e;border-radius:12px;border:1px solid #2d3748;overflow:hidden;max-width:600px;width:100%;">

        <!-- Header -->
        <tr>
          <td style="background:linear-gradient(135deg,#1e2035 0%,#252a40 100%);padding:32px 40px;text-align:center;border-bottom:1px solid #2d3748;">
            <div style="font-size:38px;margin-bottom:8px;">&#128737;&#65039;</div>
            <h1 style="margin:0;color:#818cf8;font-size:24px;font-weight:700;letter-spacing:0.5px;">Courra-Sec SIEM</h1>
            <p style="margin:6px 0 0;color:#94a3b8;font-size:13px;">Security Information &amp; Event Management</p>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding:36px 40px;">
            {body_html}
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#0f1117;padding:18px 40px;border-top:1px solid #2d3748;text-align:center;">
            <p style="margin:0 0 4px;color:#64748b;font-size:12px;">
              Courra-Sec SIEM &middot; Security Monitoring Platform &middot;
              <a href="{login_url}" style="color:#818cf8;text-decoration:none;">Go to Login</a>
            </p>
            <p style="margin:0;color:#475569;font-size:11px;">This is an automated message. Please do not reply.</p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _cta_button(url: str, label: str) -> str:
    return (
        f'<table cellpadding="0" cellspacing="0" style="margin:24px 0;">'
        f'<tr><td style="border-radius:8px;background:#6366f1;">'
        f'<a href="{url}" style="display:inline-block;padding:14px 32px;color:#fff;'
        f'text-decoration:none;font-size:15px;font-weight:600;">{label}</a>'
        f'</td></tr></table>'
    )


def _notice_box(color: str, text: str) -> str:
    return (
        f'<table cellpadding="0" cellspacing="0" style="width:100%;margin-top:20px;">'
        f'<tr><td style="background:{color}14;border:1px solid {color}40;border-left:3px solid {color};'
        f'border-radius:6px;padding:14px 18px;">'
        f'<p style="margin:0;color:{color};font-size:13px;line-height:1.5;">{text}</p>'
        f'</td></tr></table>'
    )


# ── Public email functions ────────────────────────────────────────────────────

def send_invite_email(
    to_email: str,
    to_name: str,
    org_name: str,
    role: str,
    username: str,
    temp_password: str,
    invite_token: str,
    base_url: str,
) -> bool:
    """Send a team invitation email via Resend. Returns True on success."""
    if not Config.RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not set — skipping invite email to %s", to_email)
        return False

    invite_url   = f"{base_url.rstrip('/')}/accept-invite/{invite_token}"
    login_url    = f"{base_url.rstrip('/')}/login"
    display_name = to_name or username
    role_label   = role.capitalize()

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>You've been invited to Courra-Sec</title>
</head>
<body style="margin:0;padding:0;background:#0d1117;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background:#161b22;border-radius:12px;border:1px solid #30363d;overflow:hidden;max-width:600px;width:100%;">
          <tr>
            <td style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);padding:36px 40px;text-align:center;border-bottom:1px solid #30363d;">
              <div style="font-size:40px;margin-bottom:8px;">&#128737;&#65039;</div>
              <h1 style="margin:0;color:#58a6ff;font-size:26px;font-weight:700;letter-spacing:0.5px;">Courra-Sec SIEM</h1>
              <p style="margin:6px 0 0;color:#8b949e;font-size:13px;">Security Information &amp; Event Management</p>
            </td>
          </tr>
          <tr>
            <td style="padding:36px 40px;">
              <p style="margin:0 0 16px;color:#c9d1d9;font-size:16px;">Hi <strong style="color:#f0f6fc;">{display_name}</strong>,</p>
              <p style="margin:0 0 24px;color:#8b949e;font-size:15px;line-height:1.6;">
                You've been invited to join <strong style="color:#f0f6fc;">{org_name}</strong> on Courra-Sec as a
                <strong style="color:#58a6ff;">{role_label}</strong>.
              </p>
              <table cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
                <tr>
                  <td style="background:#21262d;border:1px solid #30363d;border-radius:8px;padding:16px 24px;">
                    <table cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="padding-right:32px;">
                          <div style="margin-bottom:4px;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;font-size:11px;color:#6e7681;">Organisation</div>
                          <div style="color:#f0f6fc;font-size:15px;">{org_name}</div>
                        </td>
                        <td>
                          <div style="margin-bottom:4px;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;font-size:11px;color:#6e7681;">Role</div>
                          <div style="color:#58a6ff;font-size:15px;font-weight:600;">{role_label}</div>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
              <p style="margin:0 0 12px;color:#c9d1d9;font-size:14px;font-weight:600;">Your login credentials:</p>
              <table cellpadding="0" cellspacing="0" style="width:100%;margin-bottom:28px;">
                <tr>
                  <td style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:20px 24px;">
                    <table cellpadding="0" cellspacing="0" width="100%">
                      <tr>
                        <td style="padding-bottom:12px;">
                          <span style="color:#6e7681;font-size:12px;text-transform:uppercase;letter-spacing:0.8px;font-weight:600;">Username</span><br/>
                          <span style="color:#f0f6fc;font-size:16px;font-family:monospace;">{username}</span>
                        </td>
                      </tr>
                      <tr>
                        <td style="border-top:1px solid #21262d;padding-top:12px;">
                          <span style="color:#6e7681;font-size:12px;text-transform:uppercase;letter-spacing:0.8px;font-weight:600;">Temporary Password</span><br/>
                          <span style="color:#f85149;font-size:18px;font-family:monospace;font-weight:700;letter-spacing:1px;">{temp_password}</span>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
              <p style="margin:0 0 6px;color:#8b949e;font-size:14px;">Click the button below to accept your invitation:</p>
              <table cellpadding="0" cellspacing="0" style="margin:20px 0 28px;">
                <tr>
                  <td style="border-radius:8px;background:linear-gradient(135deg,#1f6feb 0%,#388bfd 100%);">
                    <a href="{invite_url}" style="display:inline-block;padding:14px 32px;color:#fff;text-decoration:none;font-size:15px;font-weight:600;">Accept Invitation &rarr;</a>
                  </td>
                </tr>
              </table>
              <p style="margin:0 0 4px;color:#6e7681;font-size:13px;">Or paste this link into your browser:</p>
              <p style="margin:0 0 28px;"><a href="{invite_url}" style="color:#58a6ff;font-size:13px;word-break:break-all;">{invite_url}</a></p>
              <table cellpadding="0" cellspacing="0" style="width:100%;">
                <tr>
                  <td style="background:#161b22;border:1px solid #f0883e40;border-left:3px solid #f0883e;border-radius:6px;padding:14px 18px;">
                    <p style="margin:0;color:#d29922;font-size:13px;">
                      <strong>&#9888;&#65039; Security notice:</strong> This invitation link expires in <strong>48 hours</strong>.
                      You will be prompted to change your password on first login.
                      If you did not expect this invitation, you can safely ignore this email.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="background:#0d1117;padding:20px 40px;border-top:1px solid #30363d;text-align:center;">
              <p style="margin:0 0 6px;color:#6e7681;font-size:12px;">
                Courra-Sec SIEM &middot; <a href="{login_url}" style="color:#58a6ff;text-decoration:none;">Go to Login</a>
              </p>
              <p style="margin:0;color:#484f58;font-size:11px;">This is an automated message. Please do not reply.</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    try:
        import resend
        resend.api_key = Config.RESEND_API_KEY
        resend.Emails.send({
            "from":    Config.RESEND_FROM_EMAIL,
            "to":      [to_email],
            "subject": f"You've been invited to {org_name} on Courra-Sec SIEM",
            "html":    html,
        })
        logger.info("Invite email sent to %s", to_email)
        return True
    except Exception as exc:
        logger.error("Failed to send invite email to %s: %s", to_email, exc)
        return False


def send_verification_email(
    to_email: str,
    username: str,
    org_name: str,
    token: str,
    base_url: str,
) -> bool:
    """Send email-address verification link. Returns True on success."""
    if not Config.RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not set — skipping verification email to %s", to_email)
        return False

    verify_url = f"{base_url.rstrip('/')}/verify-email/{token}"
    login_url  = f"{base_url.rstrip('/')}/login"

    body = f"""
<h2 style="margin:0 0 8px;color:#e2e8f0;font-size:20px;font-weight:600;">Verify your email address</h2>
<p style="margin:0 0 20px;color:#94a3b8;font-size:15px;line-height:1.6;">
  Hi <strong style="color:#e2e8f0;">{username}</strong>,
  welcome to <strong style="color:#e2e8f0;">{org_name}</strong> on Courra-Sec!<br/>
  Click the button below to verify your email and activate your account.
</p>

{_cta_button(verify_url, "Verify Email Address &rarr;")}

<p style="margin:4px 0 6px;color:#64748b;font-size:13px;">Or paste this link into your browser:</p>
<p style="margin:0 0 4px;">
  <a href="{verify_url}" style="color:#818cf8;font-size:13px;word-break:break-all;">{verify_url}</a>
</p>

{_notice_box("#f59e0b",
    "&#9888;&#65039; This verification link expires in <strong>24 hours</strong>. "
    "If you did not create this account, you can safely ignore this email.")}
"""

    return _resend_send(
        to_email,
        f"Verify your Courra-Sec email — {org_name}",
        _email_html(body, login_url),
    )


def send_password_changed_email(
    to_email: str,
    username: str,
    ip_address: str,
    timestamp,
) -> bool:
    """Send a security alert when a user's password is changed."""
    if not Config.RESEND_API_KEY:
        logger.debug("RESEND_API_KEY not set — skipping password-changed email to %s", to_email)
        return False

    ts_str    = timestamp.strftime("%Y-%m-%d %H:%M UTC") if hasattr(timestamp, 'strftime') else str(timestamp)
    login_url = f"{Config.APP_BASE_URL.rstrip('/')}/login"

    body = f"""
<table cellpadding="0" cellspacing="0" style="width:100%;margin-bottom:20px;">
  <tr>
    <td style="background:#3f0d0d;border:1px solid #7f1d1d;border-left:3px solid #ef4444;border-radius:8px;padding:16px 20px;">
      <p style="margin:0;color:#fca5a5;font-size:15px;font-weight:600;">
        &#128274; Your password was just changed
      </p>
    </td>
  </tr>
</table>

<p style="margin:0 0 20px;color:#94a3b8;font-size:15px;line-height:1.6;">
  Hi <strong style="color:#e2e8f0;">{username}</strong>,<br/>
  your Courra-Sec account password was successfully changed.
</p>

<table cellpadding="0" cellspacing="0" style="width:100%;margin-bottom:24px;">
  <tr>
    <td style="background:#0d1117;border:1px solid #2d3748;border-radius:8px;padding:20px 24px;">
      <table cellpadding="0" cellspacing="0" width="100%">
        <tr>
          <td style="padding-bottom:12px;">
            <span style="color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:0.8px;font-weight:600;">Account</span><br/>
            <span style="color:#e2e8f0;font-size:15px;font-family:monospace;">{username}</span>
          </td>
        </tr>
        <tr>
          <td style="border-top:1px solid #1e293b;padding:12px 0;">
            <span style="color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:0.8px;font-weight:600;">IP Address</span><br/>
            <span style="color:#e2e8f0;font-size:15px;font-family:monospace;">{ip_address or "unknown"}</span>
          </td>
        </tr>
        <tr>
          <td style="border-top:1px solid #1e293b;padding-top:12px;">
            <span style="color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:0.8px;font-weight:600;">Time</span><br/>
            <span style="color:#e2e8f0;font-size:15px;">{ts_str}</span>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>

{_notice_box("#ef4444",
    "<strong>&#9888;&#65039; If this wasn't you</strong>, your account may be compromised. "
    "Contact your administrator immediately and do not log in until the situation is resolved.")}
"""

    return _resend_send(
        to_email,
        "Security alert: your Courra-Sec password was changed",
        _email_html(body, login_url),
    )


def send_password_reset_email(
    to_email: str,
    username: str,
    reset_token: str,
    base_url: str,
) -> bool:
    """Send a password-reset link. Returns True on success."""
    if not Config.RESEND_API_KEY:
        logger.warning("RESEND_API_KEY not set — skipping password-reset email to %s", to_email)
        return False

    reset_url = f"{base_url.rstrip('/')}/reset-password/{reset_token}"
    login_url = f"{base_url.rstrip('/')}/login"

    body = f"""
<h2 style="margin:0 0 8px;color:#e2e8f0;font-size:20px;font-weight:600;">Password reset requested</h2>
<p style="margin:0 0 20px;color:#94a3b8;font-size:15px;line-height:1.6;">
  Hi <strong style="color:#e2e8f0;">{username}</strong>,<br/>
  we received a request to reset your Courra-Sec password.
  Click the button below to choose a new password.
</p>

{_cta_button(reset_url, "Reset Password &rarr;")}

<p style="margin:4px 0 6px;color:#64748b;font-size:13px;">Or paste this link into your browser:</p>
<p style="margin:0 0 4px;">
  <a href="{reset_url}" style="color:#818cf8;font-size:13px;word-break:break-all;">{reset_url}</a>
</p>

{_notice_box("#f59e0b",
    "&#9888;&#65039; This reset link expires in <strong>1 hour</strong>. "
    "If you didn't request a password reset, you can safely ignore this email — "
    "your password will not change.")}
"""

    return _resend_send(
        to_email,
        "Reset your Courra-Sec password",
        _email_html(body, login_url),
    )
