"""WebSocket security testing. MITRE ATT&CK: T1190"""
from __future__ import annotations
import uuid
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

class WebSocketModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="websocket", description="WebSocket security - CSWSH, injection, auth bypass", category="websocket",
            mitre_technique_ids=["T1190"], mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT, cwe_ids=["CWE-1385"],
            tags=["websocket", "realtime"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        return ["upgrade_check", "cswsh_check", "origin_check"]

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        paths = options.get("ws_paths", ["/ws", "/websocket", "/socket.io/", "/cable"])
        requests = []
        for path in paths:
            requests.append(AttackRequest(request_id=f"ws-{uuid.uuid4().hex[:8]}", target=target, method="GET",
                path=path, headers={"Upgrade": "websocket", "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Version": "13",
                    "Origin": "https://evil.com"}))
        return requests

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        if response.status_code == 101:
            return ModuleResult(module_name="websocket", target=request.target, status=VulnStatus.POTENTIALLY_VULNERABLE,
                payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms,
                evidence="WebSocket accepts cross-origin upgrade from evil.com (CSWSH risk)",
                severity="medium", mitre_technique_id="T1190")
        return ModuleResult(module_name="websocket", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
