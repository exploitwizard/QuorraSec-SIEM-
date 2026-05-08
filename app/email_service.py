# app/email_service.py — Resend-powered transactional email for Courra-Sec
import logging
from app.config import Config

logger = logging.getLogger(__name__)


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

    invite_url = f"{base_url.rstrip('/')}/accept-invite/{invite_token}"
    login_url  = f"{base_url.rstrip('/')}/login"
    display_name = to_name or username
    role_label = role.capitalize()

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

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);padding:36px 40px;text-align:center;border-bottom:1px solid #30363d;">
              <div style="font-size:40px;margin-bottom:8px;">🛡️</div>
              <h1 style="margin:0;color:#58a6ff;font-size:26px;font-weight:700;letter-spacing:0.5px;">Courra-Sec SIEM</h1>
              <p style="margin:6px 0 0;color:#8b949e;font-size:13px;">Security Information &amp; Event Management</p>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:36px 40px;">
              <p style="margin:0 0 16px;color:#c9d1d9;font-size:16px;">Hi <strong style="color:#f0f6fc;">{display_name}</strong>,</p>
              <p style="margin:0 0 24px;color:#8b949e;font-size:15px;line-height:1.6;">
                You've been invited to join <strong style="color:#f0f6fc;">{org_name}</strong> on Courra-Sec as a
                <strong style="color:#58a6ff;">{role_label}</strong>.
              </p>

              <!-- Role badge -->
              <table cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
                <tr>
                  <td style="background:#21262d;border:1px solid #30363d;border-radius:8px;padding:16px 24px;">
                    <table cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="color:#8b949e;font-size:13px;padding-right:32px;">
                          <div style="margin-bottom:4px;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;font-size:11px;color:#6e7681;">Organisation</div>
                          <div style="color:#f0f6fc;font-size:15px;">{org_name}</div>
                        </td>
                        <td style="color:#8b949e;font-size:13px;">
                          <div style="margin-bottom:4px;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;font-size:11px;color:#6e7681;">Role</div>
                          <div style="color:#58a6ff;font-size:15px;font-weight:600;">{role_label}</div>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>

              <!-- Credentials -->
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

              <p style="margin:0 0 6px;color:#8b949e;font-size:14px;">Click the button below to accept your invitation and set up your account:</p>

              <!-- CTA Button -->
              <table cellpadding="0" cellspacing="0" style="margin:20px 0 28px;">
                <tr>
                  <td style="border-radius:8px;background:linear-gradient(135deg,#1f6feb 0%,#388bfd 100%);">
                    <a href="{invite_url}" style="display:inline-block;padding:14px 32px;color:#ffffff;text-decoration:none;font-size:15px;font-weight:600;letter-spacing:0.3px;">Accept Invitation →</a>
                  </td>
                </tr>
              </table>

              <p style="margin:0 0 4px;color:#6e7681;font-size:13px;">Or paste this link into your browser:</p>
              <p style="margin:0 0 28px;"><a href="{invite_url}" style="color:#58a6ff;font-size:13px;word-break:break-all;">{invite_url}</a></p>

              <!-- Security notice -->
              <table cellpadding="0" cellspacing="0" style="width:100%;">
                <tr>
                  <td style="background:#161b22;border:1px solid #f0883e40;border-left:3px solid #f0883e;border-radius:6px;padding:14px 18px;">
                    <p style="margin:0;color:#d29922;font-size:13px;">
                      <strong>⚠️ Security notice:</strong> This invitation link expires in <strong>48 hours</strong>.
                      You will be prompted to change your password on first login.
                      If you did not expect this invitation, you can safely ignore this email.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#0d1117;padding:20px 40px;border-top:1px solid #30363d;text-align:center;">
              <p style="margin:0 0 6px;color:#6e7681;font-size:12px;">
                Courra-Sec SIEM · <a href="{login_url}" style="color:#58a6ff;text-decoration:none;">Go to Login</a>
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
        params = {
            "from":    Config.RESEND_FROM_EMAIL,
            "to":      [to_email],
            "subject": f"You've been invited to {org_name} on Courra-Sec SIEM",
            "html":    html,
        }
        resend.Emails.send(params)
        logger.info("Invite email sent to %s", to_email)
        return True
    except Exception as exc:
        logger.error("Failed to send invite email to %s: %s", to_email, exc)
        return False
