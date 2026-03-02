"""
iOS Security Assessment module.

Tests backend APIs for iOS-specific attack vectors including universal link
validation, IPA distribution endpoint exposure, plist configuration leakage,
keychain access indicators, App Transport Security bypass, jailbreak detection
bypass, Touch ID / Face ID bypass indicators, iOS push notification abuse,
Objective-C runtime manipulation indicators, and Swift reflection endpoints.

MITRE ATT&CK: T1406 - Obfuscated Files or Information
               T1417 - Input Capture
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ---------------------------------------------------------------------------
# Universal link validation payloads
# ---------------------------------------------------------------------------
UNIVERSAL_LINK_PAYLOADS = [
    "/.well-known/apple-app-site-association",
    "/apple-app-site-association",
    "/.well-known/apple-app-site-association?format=json",
    "/api/v1/universal-link/validate",
    "/api/v1/universal-link/resolve",
    "/api/v1/universal-link/redirect",
    "/api/v1/universal-link/config",
    "/api/v1/applinks/config",
    "/api/v1/applinks/validate",
    "/api/v1/applinks/resolve",
    "/api/v2/universal-link/resolve?url=http://evil.com",
    "/api/v2/universal-link/resolve?url=javascript:void(0)",
    "/api/v2/universal-link/resolve?url=file:///etc/passwd",
    "/api/v2/universal-link/open?target=myapp://admin/settings",
    "/api/v2/universal-link/open?target=myapp://auth/reset-password",
    "/api/v2/universal-link/open?target=myapp://payment/confirm",
    "/api/v2/universal-link/open?target=myapp://transfer?to=attacker&amount=999",
    "/api/v1/link/deferred?fallback=http://evil.com",
    "/api/v1/link/deferred?redirect=javascript:alert(1)",
    "/api/v1/link/smart?platform=ios&target=http://evil.com",
    "/api/v1/link/smart?platform=ios&fallback=file:///etc/passwd",
    "/api/v1/deeplink/ios/resolve",
    "/api/v1/deeplink/ios/redirect?url=http://127.0.0.1",
    "/api/v1/deeplink/ios/redirect?url=http://169.254.169.254/latest/meta-data/",
    "/universal-link/callback?code=test&redirect=http://evil.com",
    "/universal-link/track?event=open&target=http://evil.com",
    "/applinks?url=myapp://internal/admin/panel",
    "/applinks?url=myapp://debug/console",
    "/link/resolve?uri=myapp://settings/developer",
    "/.well-known/apple-developer-merchantid-domain-association",
    "/.well-known/apple-developer-domain-association",
    "/api/mobile/universal-link/analytics",
    "/api/mobile/universal-link/create?url=http://evil.com",
    "/api/v1/navigation/ios/resolve?route=myapp://internal/config",
    "/api/v1/navigation/ios/resolve?route=myapp://debug/flags",
]

# ---------------------------------------------------------------------------
# IPA distribution endpoint payloads
# ---------------------------------------------------------------------------
IPA_DISTRIBUTION_PAYLOADS = [
    "/app/download/release.ipa",
    "/app/download/debug.ipa",
    "/app/download/latest.ipa",
    "/app/download/enterprise.ipa",
    "/app/download/adhoc.ipa",
    "/downloads/app.ipa",
    "/downloads/app-release.ipa",
    "/downloads/app-debug.ipa",
    "/static/app.ipa",
    "/static/release/app.ipa",
    "/api/v1/app/ios/download",
    "/api/v1/app/ios/update",
    "/api/v1/app/ios/latest",
    "/api/v2/app/ios/download",
    "/api/v2/mobile/ios/update",
    "/api/mobile/ipa",
    "/api/ios/download",
    "/api/ios/update",
    "/dist/ios/app.ipa",
    "/releases/ios/latest.ipa",
    "/releases/ios/current.ipa",
    "/mobile/ios/download",
    "/mobile/app/ios",
    "/update/ios/check",
    "/update/ios/manifest.plist",
    "/version/ios/latest",
    "/version/ios/check",
    "/itms-services://?action=download-manifest&url=https://example.com/manifest.plist",
    "/api/v1/enterprise/manifest.plist",
    "/api/v1/enterprise/download",
    "/enterprise/app.ipa",
    "/enterprise/manifest.plist",
    "/.build/ios/app.ipa",
    "/.build/ios/output.json",
    "/build/ios/ExportOptions.plist",
    "/build/ios/app-release.ipa",
]

# ---------------------------------------------------------------------------
# Plist exposure and configuration leakage payloads
# ---------------------------------------------------------------------------
PLIST_EXPOSURE_PAYLOADS = [
    "/Info.plist",
    "/info.plist",
    "/app/Info.plist",
    "/config/Info.plist",
    "/api/v1/app/plist",
    "/api/v1/app/config/plist",
    "/api/v1/app/info",
    "/api/v1/config/ios",
    "/api/v1/config/plist",
    "/api/v1/config/entitlements",
    "/Entitlements.plist",
    "/entitlements.plist",
    "/embedded.mobileprovision",
    "/provisioning/profile",
    "/provisioning/certificate",
    "/GoogleService-Info.plist",
    "/google-service-info.plist",
    "/Settings.bundle/Root.plist",
    "/settings/Root.plist",
    "/config/AppConfig.plist",
    "/config/Configuration.plist",
    "/config/Environment.plist",
    "/config/Credentials.plist",
    "/config/Endpoints.plist",
    "/api/v1/mobile/config",
    "/api/v1/mobile/settings",
    "/api/v1/mobile/entitlements",
    "/api/v1/mobile/provisioning",
    "/api/v2/config/ios/current",
    "/api/v2/config/ios/settings",
    "/manifest.plist",
    "/app-manifest.plist",
    "/distribution/manifest.plist",
    "/api/debug/plist",
    "/api/internal/app-config",
    "/api/internal/ios-config",
]

# ---------------------------------------------------------------------------
# Keychain access indicator payloads
# ---------------------------------------------------------------------------
KEYCHAIN_ACCESS_PAYLOADS = [
    "/api/v1/keychain/items",
    "/api/v1/keychain/query",
    "/api/v1/keychain/export",
    "/api/v1/keychain/dump",
    "/api/v1/keychain/list",
    "/api/v1/keychain/search",
    "/api/v1/security/keychain",
    "/api/v1/security/credentials",
    "/api/v1/security/tokens",
    "/api/v1/security/certificates",
    "/api/v1/security/keys",
    "/api/v1/security/secrets",
    "/api/v1/auth/keychain",
    "/api/v1/auth/stored-credentials",
    "/api/v1/auth/saved-tokens",
    "/api/v1/auth/secure-store",
    "/api/v1/credential-store/list",
    "/api/v1/credential-store/export",
    "/api/v1/secure-storage/items",
    "/api/v1/secure-storage/dump",
    "/api/v1/token-store/list",
    "/api/v1/token-store/export",
    "/api/debug/keychain",
    "/api/debug/credentials",
    "/api/debug/secure-store",
    "/api/debug/token-store",
    "/api/internal/keychain-items",
    "/api/internal/stored-secrets",
    "/api/internal/credential-dump",
    "/keychain-backup.json",
    "/keychain-export.json",
    "/keychain/items.json",
    "/security/keychain-items",
    "/debug/keychain-dump",
]

# ---------------------------------------------------------------------------
# App Transport Security bypass payloads
# ---------------------------------------------------------------------------
ATS_BYPASS_PAYLOADS = [
    "/api/v1/config/ats",
    "/api/v1/config/transport-security",
    "/api/v1/config/network-policy",
    "/api/v1/security/ats",
    "/api/v1/security/transport",
    "/api/v1/security/tls-config",
    "/api/v1/security/ssl-config",
    "/api/v1/network/config",
    "/api/v1/network/policy",
    "/api/v1/network/exceptions",
    "/api/v1/network/allowed-domains",
    "/api/v1/network/certificate-pins",
    "/api/v2/security/ats-exceptions",
    "/api/v2/security/ats-config",
    "/api/v2/security/network-exceptions",
    "/api/v2/security/tls-exceptions",
    "/debug/ats-config",
    "/debug/network-policy",
    "/debug/ssl-info",
    "/debug/tls-version",
    "/debug/certificate-chain",
    "/debug/cipher-suites",
    "/api/health/ssl",
    "/api/health/tls",
    "/api/health/certificate",
    "/api/internal/ats-config",
    "/api/internal/network-config",
    "/api/internal/ssl-bypass",
    "/config/ats-exceptions.json",
    "/config/network-policy.json",
    "/config/tls-exceptions.json",
    "/config/allowed-insecure-domains.json",
    "/NSAppTransportSecurity",
    "/api/v1/config/NSAppTransportSecurity",
]

# ---------------------------------------------------------------------------
# Jailbreak detection bypass payloads
# ---------------------------------------------------------------------------
JAILBREAK_BYPASS_PAYLOADS = [
    "/api/v1/device/check",
    "/api/v1/device/integrity",
    "/api/v1/device/status",
    "/api/v1/device/verify",
    "/api/v1/device/attestation",
    "/api/v1/device/trust",
    "/api/v1/security/device-check",
    "/api/v1/security/integrity-check",
    "/api/v1/security/jailbreak-check",
    "/api/v1/security/root-check",
    "/api/v1/security/tamper-check",
    "/api/v1/security/environment-check",
    "/api/v1/attest/device",
    "/api/v1/attest/app",
    "/api/v1/attest/key",
    "/api/v2/device/integrity-token",
    "/api/v2/device/attestation-result",
    "/api/v2/security/device-trust",
    "/api/v2/security/app-integrity",
    "/api/v2/security/environment-status",
    "/api/mobile/device-check",
    "/api/mobile/integrity",
    "/api/mobile/attestation",
    "/api/mobile/verify-device",
    "/api/mobile/jailbreak-status",
    "/api/debug/device-check",
    "/api/debug/integrity",
    "/api/debug/jailbreak",
    "/api/internal/device-trust",
    "/api/internal/integrity-bypass",
    "/api/internal/jailbreak-override",
    "/api/v1/devicecheck/validate",
    "/api/v1/app-attest/verify",
    "/api/v1/device/environment",
]

# ---------------------------------------------------------------------------
# Touch ID / Face ID bypass indicator payloads
# ---------------------------------------------------------------------------
BIOMETRIC_BYPASS_PAYLOADS = [
    "/api/v1/auth/biometric",
    "/api/v1/auth/touchid",
    "/api/v1/auth/faceid",
    "/api/v1/auth/biometric/verify",
    "/api/v1/auth/biometric/enroll",
    "/api/v1/auth/biometric/status",
    "/api/v1/auth/biometric/bypass",
    "/api/v1/auth/biometric/fallback",
    "/api/v1/auth/local-auth",
    "/api/v1/auth/local-auth/verify",
    "/api/v1/auth/local-auth/status",
    "/api/v1/auth/passcode-fallback",
    "/api/v1/auth/device-auth",
    "/api/v1/auth/device-auth/verify",
    "/api/v2/auth/biometric-token",
    "/api/v2/auth/biometric-challenge",
    "/api/v2/auth/biometric-result",
    "/api/v2/auth/biometric-bypass",
    "/api/mobile/auth/biometric",
    "/api/mobile/auth/fingerprint",
    "/api/mobile/auth/face",
    "/api/mobile/auth/verify-biometric",
    "/api/debug/biometric",
    "/api/debug/auth/biometric-status",
    "/api/debug/auth/biometric-override",
    "/api/internal/biometric-config",
    "/api/internal/biometric-bypass",
    "/api/internal/auth-fallback",
    "/api/v1/security/biometric-policy",
    "/api/v1/security/biometric-config",
    "/api/v1/security/local-auth-config",
    "/biometric/config.json",
    "/auth/biometric-settings.json",
    "/config/biometric-policy.json",
]

# ---------------------------------------------------------------------------
# iOS push notification abuse payloads
# ---------------------------------------------------------------------------
PUSH_NOTIFICATION_PAYLOADS = [
    "/api/v1/push/register",
    "/api/v1/push/send",
    "/api/v1/push/broadcast",
    "/api/v1/push/topic",
    "/api/v1/push/config",
    "/api/v1/push/tokens",
    "/api/v1/push/devices",
    "/api/v1/push/certificate",
    "/api/v1/push/apns-config",
    "/api/v1/notifications/send",
    "/api/v1/notifications/broadcast",
    "/api/v1/notifications/config",
    "/api/v1/notifications/tokens",
    "/api/v1/notifications/devices",
    "/api/v1/notifications/topics",
    "/api/v2/push/register?token=test",
    "/api/v2/push/send?to=all&message=test",
    "/api/v2/push/send?topic=admin&message=test",
    "/api/v2/push/unregister",
    "/api/v2/notifications/mass-send",
    "/api/v2/notifications/admin-broadcast",
    "/api/mobile/push/register",
    "/api/mobile/push/config",
    "/api/mobile/push/certificate",
    "/api/mobile/notifications/send",
    "/api/debug/push/send",
    "/api/debug/push/tokens",
    "/api/debug/push/test",
    "/api/debug/notifications/send-test",
    "/api/internal/push/apns-key",
    "/api/internal/push/certificate",
    "/api/internal/push/auth-key",
    "/push/apns-cert.p12",
    "/push/AuthKey.p8",
    "/push/config.json",
]

# ---------------------------------------------------------------------------
# Objective-C runtime manipulation indicator payloads
# ---------------------------------------------------------------------------
OBJC_RUNTIME_PAYLOADS = [
    "/api/v1/runtime/classes",
    "/api/v1/runtime/methods",
    "/api/v1/runtime/selectors",
    "/api/v1/runtime/protocols",
    "/api/v1/runtime/properties",
    "/api/v1/runtime/ivars",
    "/api/v1/runtime/categories",
    "/api/v1/runtime/dump",
    "/api/v1/runtime/inspect",
    "/api/v1/runtime/swizzle",
    "/api/v1/app/classes",
    "/api/v1/app/methods",
    "/api/v1/app/symbols",
    "/api/v1/app/headers",
    "/api/v1/app/frameworks",
    "/api/v1/app/dylibs",
    "/api/v1/debug/class-dump",
    "/api/v1/debug/method-trace",
    "/api/v1/debug/symbol-table",
    "/api/v1/debug/memory-map",
    "/api/v1/debug/heap-dump",
    "/api/v1/debug/stack-trace",
    "/api/v2/runtime/class-list",
    "/api/v2/runtime/method-list",
    "/api/v2/runtime/framework-list",
    "/api/v2/runtime/dynamic-libs",
    "/api/debug/objc-classes",
    "/api/debug/objc-methods",
    "/api/debug/objc-protocols",
    "/api/debug/runtime-info",
    "/api/internal/class-dump",
    "/api/internal/symbol-table",
    "/api/internal/dylib-list",
    "/api/internal/framework-info",
]

# ---------------------------------------------------------------------------
# Swift reflection endpoint payloads
# ---------------------------------------------------------------------------
SWIFT_REFLECTION_PAYLOADS = [
    "/api/v1/reflect/types",
    "/api/v1/reflect/mirrors",
    "/api/v1/reflect/metadata",
    "/api/v1/reflect/dump",
    "/api/v1/reflect/modules",
    "/api/v1/reflect/protocols",
    "/api/v1/swift/types",
    "/api/v1/swift/metadata",
    "/api/v1/swift/modules",
    "/api/v1/swift/protocols",
    "/api/v1/swift/extensions",
    "/api/v1/swift/generics",
    "/api/v1/app/swift-types",
    "/api/v1/app/swift-metadata",
    "/api/v1/app/swift-modules",
    "/api/v1/app/type-info",
    "/api/v1/app/module-list",
    "/api/v1/debug/swift-dump",
    "/api/v1/debug/type-metadata",
    "/api/v1/debug/module-info",
    "/api/v1/debug/reflection-data",
    "/api/v2/reflect/type-list",
    "/api/v2/reflect/module-list",
    "/api/v2/reflect/protocol-list",
    "/api/v2/reflect/mirror-dump",
    "/api/debug/swift-types",
    "/api/debug/swift-modules",
    "/api/debug/swift-metadata",
    "/api/debug/reflection-info",
    "/api/internal/swift-dump",
    "/api/internal/type-metadata",
    "/api/internal/module-info",
    "/api/internal/reflection-data",
    "/api/internal/swift-symbols",
    "/api/internal/swift-generics",
]

# Combine all payloads
ALL_IOS_PAYLOADS = (
    UNIVERSAL_LINK_PAYLOADS
    + IPA_DISTRIBUTION_PAYLOADS
    + PLIST_EXPOSURE_PAYLOADS
    + KEYCHAIN_ACCESS_PAYLOADS
    + ATS_BYPASS_PAYLOADS
    + JAILBREAK_BYPASS_PAYLOADS
    + BIOMETRIC_BYPASS_PAYLOADS
    + PUSH_NOTIFICATION_PAYLOADS
    + OBJC_RUNTIME_PAYLOADS
    + SWIFT_REFLECTION_PAYLOADS
)

# ---------------------------------------------------------------------------
# Vulnerability indicators
# ---------------------------------------------------------------------------
IOS_INDICATORS: list[tuple[str, str, str]] = [
    # Universal link / AASA indicators
    ("applinks", "Apple App Site Association applinks config found", "medium"),
    ("webcredentials", "Apple webcredentials configuration found", "high"),
    ("activitycontinuation", "Apple activity continuation config found", "medium"),
    ("appclips", "Apple App Clips configuration found", "medium"),
    ("\"appID\"", "Apple app ID exposed in AASA", "medium"),
    ("\"paths\"", "Universal link paths configuration exposed", "medium"),
    ("\"components\"", "Universal link components configuration exposed", "medium"),
    ("apple-app-site-association", "AASA file reference found", "low"),

    # IPA / distribution indicators
    ("application/x-itunes-ipa", "IPA file served directly", "critical"),
    ("software-package", "iOS software package content detected", "high"),
    ("itms-services://", "iTunes services protocol URL found", "high"),
    ("enterprise-distribution", "Enterprise distribution reference found", "critical"),
    ("ad-hoc-distribution", "Ad-hoc distribution reference found", "high"),
    ("manifest.plist", "OTA distribution manifest reference found", "high"),
    ("bundle-identifier", "iOS bundle identifier exposed", "medium"),
    ("bundle-version", "iOS bundle version exposed", "medium"),
    ("CFBundleIdentifier", "CoreFoundation bundle identifier exposed", "medium"),
    ("CFBundleName", "CoreFoundation bundle name exposed", "low"),
    ("CFBundleVersion", "CoreFoundation bundle version exposed", "low"),

    # Plist configuration indicators
    ("<!DOCTYPE plist", "Property list XML content detected", "high"),
    ("<plist version", "Property list file detected", "high"),
    ("NSAppTransportSecurity", "App Transport Security config exposed", "high"),
    ("NSAllowsArbitraryLoads", "ATS arbitrary loads setting exposed", "critical"),
    ("NSExceptionDomains", "ATS exception domains exposed", "high"),
    ("NSExceptionAllowsInsecureHTTPLoads", "ATS insecure HTTP exception found", "critical"),
    ("NSIncludesSubdomains", "ATS subdomain inclusion setting exposed", "medium"),
    ("NSTemporaryExceptionMinimumTLSVersion", "ATS minimum TLS exception found", "high"),
    ("UIBackgroundModes", "iOS background modes exposed", "medium"),
    ("UIRequiredDeviceCapabilities", "iOS required capabilities exposed", "low"),
    ("CFBundleURLSchemes", "iOS URL schemes exposed", "high"),
    ("com.apple.developer", "Apple developer entitlement found", "high"),
    ("keychain-access-groups", "Keychain access groups exposed", "critical"),
    ("application-identifier", "Application identifier entitlement exposed", "medium"),
    ("aps-environment", "Push notification environment exposed", "medium"),
    ("com.apple.security", "Apple security entitlement found", "high"),

    # Keychain indicators
    ("kSecClass", "Keychain class reference found", "high"),
    ("kSecAttrAccessible", "Keychain accessibility attribute found", "high"),
    ("kSecAttrAccessibleWhenUnlocked", "Keychain when-unlocked access found", "medium"),
    ("kSecAttrAccessibleAfterFirstUnlock", "Keychain after-first-unlock access found", "high"),
    ("kSecAttrAccessibleAlways", "Keychain always-accessible found", "critical"),
    ("kSecValueData", "Keychain value data reference found", "high"),
    ("SecItemCopyMatching", "Keychain item query reference found", "high"),
    ("SecItemAdd", "Keychain item add reference found", "medium"),
    ("keychain-items", "Keychain items reference found", "high"),
    ("keychain-dump", "Keychain dump reference found", "critical"),

    # Jailbreak detection indicators
    ("jailbreak", "Jailbreak reference found", "medium"),
    ("Cydia", "Cydia reference found (jailbreak indicator)", "medium"),
    ("MobileSubstrate", "MobileSubstrate reference found", "high"),
    ("/Applications/Cydia.app", "Cydia app path found", "high"),
    ("/Library/MobileSubstrate", "MobileSubstrate path found", "high"),
    ("/bin/bash", "Bash binary path found (jailbreak check)", "medium"),
    ("/usr/sbin/sshd", "SSHD path found (jailbreak check)", "medium"),
    ("canOpenURL", "canOpenURL reference found", "low"),
    ("isJailbroken", "Jailbreak check method reference found", "medium"),
    ("deviceIntegrity", "Device integrity check reference found", "low"),

    # Biometric auth indicators
    ("LAContext", "LocalAuthentication context reference found", "medium"),
    ("evaluatePolicy", "Biometric policy evaluation reference found", "high"),
    ("LAPolicyDeviceOwnerAuthenticationWithBiometrics", "Biometric auth policy found", "high"),
    ("LAPolicyDeviceOwnerAuthentication", "Device owner auth policy found", "medium"),
    ("touchIDAuthenticationAllowableReuseDuration", "Touch ID reuse duration found", "high"),
    ("biometricType", "Biometric type reference found", "medium"),
    ("canEvaluatePolicy", "Policy evaluation capability check found", "low"),
    ("biometric-bypass", "Biometric bypass reference found", "critical"),
    ("biometric-fallback", "Biometric fallback reference found", "high"),

    # Push notification indicators
    ("apns-token", "APNS token reference found", "high"),
    ("apns-push-type", "APNS push type header found", "medium"),
    ("apns-topic", "APNS topic reference found", "medium"),
    ("apns-priority", "APNS priority reference found", "low"),
    ("AuthKey_", "APNS authentication key reference found", "critical"),
    ("apns-cert", "APNS certificate reference found", "critical"),
    ("push-certificate", "Push certificate reference found", "critical"),
    ("aps", "Apple Push Service reference found", "low"),
    ("device-token", "Device token reference found", "high"),

    # Objective-C runtime indicators
    ("objc_getClass", "ObjC runtime class access found", "high"),
    ("objc_msgSend", "ObjC runtime message send found", "high"),
    ("method_exchangeImplementations", "ObjC method swizzling found", "critical"),
    ("class_addMethod", "ObjC dynamic method addition found", "high"),
    ("class_replaceMethod", "ObjC method replacement found", "critical"),
    ("object_getClass", "ObjC runtime class inspection found", "high"),
    ("sel_registerName", "ObjC selector registration found", "medium"),
    ("protocol_getMethodDescription", "ObjC protocol method description found", "medium"),
    ("class-dump", "Class dump reference found", "high"),
    ("_objc_", "ObjC internal runtime reference found", "high"),

    # Swift reflection indicators
    ("Swift.Mirror", "Swift Mirror reflection found", "high"),
    ("swift_getTypeByMangledName", "Swift type lookup by mangled name found", "high"),
    ("swift_metadata", "Swift metadata reference found", "high"),
    ("_swift_", "Swift internal runtime reference found", "medium"),
    ("SwiftObject", "Swift object reference found", "medium"),
    ("swift_reflect", "Swift reflection reference found", "high"),
    ("type-metadata", "Type metadata reference found", "medium"),
    ("reflection-data", "Reflection data reference found", "high"),
    ("module-info", "Module information reference found", "medium"),
    ("symbol-table", "Symbol table reference found", "high"),
]


class IOSSecurityModule(BaseAttackModule):
    """
    iOS Security Assessment module.

    Performs comprehensive testing of backend APIs for iOS-specific attack
    surfaces including universal link validation abuse, IPA distribution
    endpoint exposure, plist configuration leakage, keychain access
    indicators, App Transport Security bypass, jailbreak detection bypass,
    Touch ID / Face ID bypass indicators, iOS push notification abuse,
    Objective-C runtime manipulation indicators, and Swift reflection
    endpoint exposure.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="ios_security",
            description=(
                "iOS security assessment - universal link abuse, IPA distribution "
                "endpoint exposure, plist leakage, keychain access, ATS bypass, "
                "jailbreak detection bypass, biometric bypass, push notification "
                "abuse, ObjC runtime manipulation, Swift reflection"
            ),
            category="mobile",
            mitre_technique_ids=["T1406", "T1417"],
            mitre_technique_names=[
                "Obfuscated Files or Information",
                "Input Capture",
            ],
            auth_level_required=AuthorizationLevel.FULL,
            owasp_category="M1:2024 - Improper Credential Usage",
            cwe_ids=["CWE-295", "CWE-311", "CWE-693", "CWE-200", "CWE-522", "CWE-287"],
            tags=[
                "ios", "mobile", "ipa", "universal-link", "plist", "keychain",
                "ats", "jailbreak", "biometric", "touchid", "faceid",
                "push-notification", "objc-runtime", "swift-reflection",
            ],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """Retrieve iOS security testing payloads."""
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("ios_security", limit=500)
            if db_payloads:
                return db_payloads

        target_name = self._extract_target_name(target)
        resolved: list[str] = []
        for payload in ALL_IOS_PAYLOADS:
            resolved.append(payload.replace("{target}", target_name))

        return resolved

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        requests: list[AttackRequest] = []

        for payload in payloads:
            req_id = str(uuid.uuid4())[:8]

            # IPA download requests need Accept header for binary
            if ".ipa" in payload:
                requests.append(AttackRequest(
                    request_id=f"ios-ipa-{req_id}",
                    target=target,
                    method="GET",
                    path=payload,
                    headers={
                        "X-BAS-Payload": payload,
                        "Accept": "application/octet-stream",
                        "User-Agent": "CFNetwork/1399 Darwin/22.1.0",
                    },
                    timeout=options.get("timeout", 15.0),
                    follow_redirects=options.get("follow_redirects", False),
                ))
                continue

            # Plist requests need appropriate Accept header
            if ".plist" in payload or "plist" in payload.lower():
                requests.append(AttackRequest(
                    request_id=f"ios-plist-{req_id}",
                    target=target,
                    method="GET",
                    path=payload,
                    headers={
                        "X-BAS-Payload": payload,
                        "Accept": "application/xml, text/xml, application/x-plist",
                        "User-Agent": "CFNetwork/1399 Darwin/22.1.0",
                    },
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=False,
                ))
                continue

            # Apple app site association requests
            if "apple-app-site-association" in payload or "apple-developer" in payload:
                requests.append(AttackRequest(
                    request_id=f"ios-aasa-{req_id}",
                    target=target,
                    method="GET",
                    path=payload,
                    headers={
                        "X-BAS-Payload": payload,
                        "Accept": "application/json",
                        "User-Agent": "swcd (unknown version) CFNetwork/1399 Darwin/22.1.0",
                    },
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=False,
                ))
                continue

            # Universal link / deeplink redirect payloads
            if "universal-link" in payload or "applink" in payload or "deeplink" in payload:
                requests.append(AttackRequest(
                    request_id=f"ios-ulink-{req_id}",
                    target=target,
                    method="GET",
                    path=payload,
                    headers={
                        "X-BAS-Payload": payload[:200],
                        "User-Agent": "CFNetwork/1399 Darwin/22.1.0",
                        "X-Requested-With": "com.example.iosapp",
                    },
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=False,
                ))
                continue

            # Push notification certificate/key requests
            if ".p12" in payload or ".p8" in payload:
                requests.append(AttackRequest(
                    request_id=f"ios-push-{req_id}",
                    target=target,
                    method="GET",
                    path=payload,
                    headers={
                        "X-BAS-Payload": payload,
                        "Accept": "application/octet-stream, application/x-pkcs12",
                        "User-Agent": "CFNetwork/1399 Darwin/22.1.0",
                    },
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=False,
                ))
                continue

            # Standard path-based payloads
            requests.append(AttackRequest(
                request_id=f"ios-probe-{req_id}",
                target=target,
                method="GET",
                path=payload,
                headers={
                    "X-BAS-Payload": payload[:200],
                    "User-Agent": "CFNetwork/1399 Darwin/22.1.0",
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
                module_name="ios_security",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"error": response.error},
            )

        # Check against indicator list
        for indicator, desc, severity in IOS_INDICATORS:
            if indicator in body:
                status = (
                    VulnStatus.VULNERABLE
                    if severity in ("critical", "high")
                    else VulnStatus.POTENTIALLY_VULNERABLE
                )
                return ModuleResult(
                    module_name="ios_security",
                    target=request.target,
                    status=status,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"iOS security issue: {desc} (indicator: '{indicator}')",
                    severity=severity,
                    mitre_technique_id="T1406",
                    detail={
                        "detection_type": "ios_indicator",
                        "indicator": indicator,
                        "headers": dict(response.headers),
                    },
                )

        # Regex-based detection patterns
        regex_patterns = [
            (r"com\.[a-z]+\.[a-z]+(?:\.[A-Z][a-zA-Z]+)+",
             "iOS bundle identifier or class name exposed", "high"),
            (r"(?i)team[_-]?id\s*[=:]\s*[A-Z0-9]{10}",
             "Apple Team ID exposed", "high"),
            (r"[A-Z0-9]{10}\.[a-z]+\.[a-z]+\.[a-z]+",
             "Full application identifier (TeamID.BundleID) exposed", "high"),
            (r"(?i)apns[_-]?(?:key|token|secret|cert)\s*[=:]\s*\S+",
             "APNS credential exposed", "critical"),
            (r"(?i)(?:keychain|secure[_-]?store)[_-]?(?:password|secret|token|key)\s*[=:]\s*\S+",
             "Keychain or secure storage credential exposed", "critical"),
            (r"(?i)NSAllowsArbitraryLoads\s*</key>\s*<true/>",
             "ATS arbitrary loads enabled in plist", "critical"),
            (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
             "Private key found in response", "critical"),
            (r"-----BEGIN CERTIFICATE-----",
             "Certificate found in response", "high"),
            (r"(?i)provisioning[_-]?profile\s*[=:]\s*\S+",
             "Provisioning profile reference exposed", "high"),
            (r"(?i)entitlements?\s*[=:{]",
             "Entitlements configuration exposed", "high"),
        ]
        for pattern, desc, severity in regex_patterns:
            match = re.search(pattern, body)
            if match:
                return ModuleResult(
                    module_name="ios_security",
                    target=request.target,
                    status=VulnStatus.VULNERABLE if severity in ("critical", "high") else VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"iOS security issue: {desc} (match: '{match.group()[:80]}')",
                    severity=severity,
                    mitre_technique_id="T1417",
                    detail={"detection_type": "regex_pattern", "pattern": pattern},
                )

        # IPA binary response detection via Content-Type header
        content_type = response.headers.get("content-type", "").lower()
        if "octet-stream" in content_type or "x-itunes-ipa" in content_type:
            if response.status_code == 200 and ".ipa" in (request.path or ""):
                return ModuleResult(
                    module_name="ios_security",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview="[binary IPA content]",
                    elapsed_ms=response.elapsed_ms,
                    evidence="IPA file served via unprotected endpoint",
                    severity="critical",
                    mitre_technique_id="T1406",
                    detail={
                        "detection_type": "ipa_download",
                        "content_type": content_type,
                        "content_length": response.headers.get("content-length", "unknown"),
                    },
                )

        # PKCS12 / P8 key file detection
        if "pkcs12" in content_type or "x-pkcs12" in content_type:
            if response.status_code == 200:
                return ModuleResult(
                    module_name="ios_security",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview="[binary PKCS12 content]",
                    elapsed_ms=response.elapsed_ms,
                    evidence="PKCS12 certificate/key file served (possible APNS credentials)",
                    severity="critical",
                    mitre_technique_id="T1417",
                    detail={
                        "detection_type": "pkcs12_download",
                        "content_type": content_type,
                    },
                )

        # Plist content detection via Content-Type
        if "plist" in content_type or "application/xml" in content_type:
            if response.status_code == 200 and ("<!DOCTYPE plist" in body or "<plist" in body):
                return ModuleResult(
                    module_name="ios_security",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="Property list file exposed via API endpoint",
                    severity="high",
                    mitre_technique_id="T1406",
                    detail={
                        "detection_type": "plist_exposure",
                        "content_type": content_type,
                    },
                )

        # AASA file detection (valid JSON with applinks)
        if "apple-app-site-association" in (request.path or ""):
            if response.status_code == 200 and len(body.strip()) > 2:
                return ModuleResult(
                    module_name="ios_security",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="Apple App Site Association file accessible (review path patterns)",
                    severity="medium",
                    mitre_technique_id="T1406",
                    detail={"detection_type": "aasa_exposure"},
                )

        # Sensitive path content detection
        sensitive_paths = [
            "/keychain", "/secure-store", "/credential", "/token-store",
            "/debug/", "/internal/", "/runtime/", "/reflect/",
            "/biometric", "/push/", "/notification/", "/entitlement",
            "/provisioning", "/mobileprovision",
        ]
        if response.status_code == 200 and len(body.strip()) > 0:
            if any(sp in (request.path or "") for sp in sensitive_paths):
                return ModuleResult(
                    module_name="ios_security",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Sensitive iOS path returned content: {request.path}",
                    severity="medium",
                    mitre_technique_id="T1417",
                    detail={"detection_type": "sensitive_path_content"},
                )

        return ModuleResult(
            module_name="ios_security",
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
