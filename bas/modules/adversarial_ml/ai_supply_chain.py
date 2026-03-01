"""
AI Supply Chain Security testing module.

Tests for vulnerabilities in AI model supply chains including exposed model
registries, unsafe deserialization endpoints, dependency confusion, leaked
model artifacts, exposed notebooks, and ML pipeline infrastructure.

MITRE ATT&CK: T1584 - Compromise Infrastructure
               T1195 - Supply Chain Compromise

For authorized red team testing of AI/ML systems only.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from bas.core.executor import AttackRequest, AttackResponse
from bas.core.scope import AuthorizationLevel
from bas.modules.base_module import BaseAttackModule, ModuleMetadata, ModuleResult, VulnStatus


# ── Model registry probing paths ─────────────────────────────────────────────
MODEL_REGISTRY_PATHS = [
    "/v2/_catalog",
    "/v2/models/tags/list",
    "/v2/models",
    "/api/models",
    "/models",
    "/api/v1/models",
    "/api/v2/models",
    "/api/models/list",
    "/api/v1/model-registry",
    "/api/v1/registered-models/list",
    "/api/v1/registered-models/search",
]

# ── Model hosting platform paths ─────────────────────────────────────────────
MODEL_HOSTING_PATHS = [
    "/huggingface/",
    "/huggingface/api/models",
    "/mlflow/",
    "/mlflow/api/2.0/mlflow/",
    "/mlflow/api/2.0/mlflow/registered-models/list",
    "/mlflow/api/2.0/mlflow/experiments/list",
    "/wandb/",
    "/wandb/api/v1/",
    "/neptune/",
    "/neptune/api/v1/",
    "/bentoml/",
    "/bentoml/api/v1/",
    "/seldon/",
    "/seldon/api/v1/",
    "/triton/",
    "/triton/v2/models",
    "/torchserve/",
    "/torchserve/models",
    "/tensorflow/serving/v1/models",
]

# ── Cache and storage exposure paths ─────────────────────────────────────────
CACHE_EXPOSURE_PATHS = [
    "/.cache/huggingface/",
    "/.cache/huggingface/hub/",
    "/.cache/huggingface/datasets/",
    "/.cache/torch/",
    "/.cache/torch/hub/",
    "/.cache/transformers/",
    "/.cache/pip/",
    "/.cache/conda/",
    "/.local/share/huggingface/",
    "/tmp/models/",
    "/tmp/checkpoints/",
    "/var/ml/models/",
    "/opt/ml/model/",
    "/opt/ml/input/",
    "/opt/ml/output/",
]

# ── Serialization attack / model upload endpoints ────────────────────────────
SERIALIZATION_PATHS = [
    "/upload/model",
    "/api/models/upload",
    "/api/v1/models/upload",
    "/api/v1/model/import",
    "/api/models/import",
    "/api/v1/models/deploy",
    "/models/upload",
    "/models/import",
    "/inference/upload",
    "/api/serving/upload",
]

# ── Dependency files ─────────────────────────────────────────────────────────
DEPENDENCY_PATHS = [
    "/requirements.txt",
    "/environment.yml",
    "/environment.yaml",
    "/Pipfile",
    "/Pipfile.lock",
    "/pyproject.toml",
    "/conda.yml",
    "/conda.yaml",
    "/setup.py",
    "/setup.cfg",
    "/poetry.lock",
    "/pdm.lock",
    "/pip.conf",
    "/constraints.txt",
    "/dev-requirements.txt",
    "/requirements-dev.txt",
    "/requirements-ml.txt",
]

# ── Model artifact file extensions ───────────────────────────────────────────
MODEL_ARTIFACT_PATHS = [
    # PyTorch
    "/model.pt",
    "/model.pth",
    "/models/model.pt",
    "/models/model.pth",
    "/checkpoints/latest.pt",
    "/checkpoints/latest.pth",
    "/checkpoints/best.pt",
    "/weights/model.pt",
    "/weights/model.pth",
    # TensorFlow / Keras
    "/model.h5",
    "/model.keras",
    "/models/model.h5",
    "/weights/model.h5",
    "/saved_model/saved_model.pb",
    "/saved_model.pb",
    # ONNX
    "/model.onnx",
    "/models/model.onnx",
    # Pickle / Joblib / Sklearn
    "/model.pkl",
    "/model.joblib",
    "/models/model.pkl",
    "/models/model.joblib",
    "/pipeline.pkl",
    # GGUF / GGML (LLM quantized)
    "/model.gguf",
    "/model.ggml",
    "/models/model.gguf",
    "/models/model.ggml",
    # SafeTensors
    "/model.safetensors",
    "/models/model.safetensors",
    "/weights/model.safetensors",
    # Generic binary
    "/model.bin",
    "/models/model.bin",
    "/weights/model.bin",
    "/pytorch_model.bin",
    # Config files
    "/config.json",
    "/model_config.json",
    "/tokenizer.json",
    "/tokenizer_config.json",
    "/vocab.json",
    "/merges.txt",
    "/special_tokens_map.json",
]

# ── Jupyter / Notebook exposure ──────────────────────────────────────────────
NOTEBOOK_PATHS = [
    "/api/kernels",
    "/api/sessions",
    "/api/terminals",
    "/api/contents",
    "/notebooks/",
    "/notebook.ipynb",
    "/lab",
    "/lab/api/settings",
    "/lab/api/workspaces",
    "/.ipynb_checkpoints/",
    "/api/kernelspecs",
    "/nbconvert/",
    "/tree",
    "/voila/",
]

# ── ML pipeline / experiment tracking exposure ───────────────────────────────
PIPELINE_PATHS = [
    "/mlflow/api/2.0/mlflow/experiments/search",
    "/mlflow/api/2.0/mlflow/runs/search",
    "/mlflow/api/2.0/mlflow/artifacts/list",
    "/mlflow/api/2.0/mlflow/model-versions/search",
    "/api/experiments",
    "/api/experiments/list",
    "/api/runs",
    "/api/runs/list",
    "/api/artifacts",
    "/tensorboard/",
    "/tensorboard/data/runs",
    "/tensorboard/data/scalars",
    "/api/logdir",
    "/airflow/api/v1/dags",
    "/airflow/api/v1/dags?limit=100",
    "/airflow/api/v1/dag_runs",
    "/prefect/api/",
    "/prefect/api/flows",
    "/prefect/api/flow_runs",
    "/kubeflow/",
    "/kubeflow/pipeline/apis/v1beta1/pipelines",
    "/kubeflow/pipeline/apis/v1beta1/runs",
    "/dagster/graphql",
    "/metaflow/",
    "/ray/api/",
    "/ray/dashboard/",
]

# ── Build the combined payload list ──────────────────────────────────────────
DEFAULT_SUPPLY_CHAIN_PAYLOADS: list[str] = (
    MODEL_REGISTRY_PATHS
    + MODEL_HOSTING_PATHS
    + CACHE_EXPOSURE_PATHS
    + SERIALIZATION_PATHS
    + DEPENDENCY_PATHS
    + MODEL_ARTIFACT_PATHS
    + NOTEBOOK_PATHS
    + PIPELINE_PATHS
)

# ── Response indicators for each category ────────────────────────────────────
REGISTRY_INDICATORS = [
    "repositories", "models", "tags", "latest", "digest",
    "model_name", "model_version", "registered_model",
    "experiment_id", "run_id", "artifact",
]

MODEL_FILE_CONTENT_TYPES = [
    "application/octet-stream",
    "application/x-protobuf",
    "application/x-hdf5",
    "application/zip",
    "application/gzip",
    "application/x-tar",
    "binary/octet-stream",
]

NOTEBOOK_INDICATORS = [
    "kernel_id", "session_id", "notebook_path",
    "kernelspec", "nbformat", "cells",
    "execution_count", "cell_type",
]

PIPELINE_INDICATORS = [
    "experiment_id", "run_id", "dag_id",
    "pipeline_id", "flow_id", "task_id",
    "artifact_uri", "metric", "parameter",
    "scalars", "run_name", "start_time",
]

DEPENDENCY_INDICATORS = [
    "torch", "tensorflow", "transformers", "numpy", "pandas",
    "scikit-learn", "keras", "onnx", "mlflow", "wandb",
    "huggingface", "accelerate", "datasets", "tokenizers",
    "langchain", "openai", "anthropic", "vllm", "llama",
]

VULNERABLE_DEPENDENCY_PATTERNS = [
    re.compile(r"torch[=<>!]=?\s*[01]\.", re.IGNORECASE),
    re.compile(r"tensorflow[=<>!]=?\s*[01]\.", re.IGNORECASE),
    re.compile(r"transformers[=<>!]=?\s*[0-3]\.", re.IGNORECASE),
    re.compile(r"pickle", re.IGNORECASE),
    re.compile(r"joblib[=<>!]=?\s*0\.", re.IGNORECASE),
    re.compile(r"numpy[=<>!]=?\s*1\.[012]\d\.", re.IGNORECASE),
]


class AISupplyChainModule(BaseAttackModule):
    """
    AI Supply Chain Security testing module.

    Probes for exposed model registries, unsafe model upload/deserialization
    endpoints, leaked dependency files, exposed model artifacts, Jupyter
    notebook servers, and ML pipeline infrastructure.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            name="ai_supply_chain",
            description=(
                "AI Supply Chain Security testing - model registry probing, "
                "serialization attacks, dependency confusion, model artifact "
                "exposure, notebook discovery, ML pipeline enumeration"
            ),
            category="adversarial_ml",
            mitre_technique_ids=["T1584", "T1195"],
            mitre_technique_names=["Compromise Infrastructure", "Supply Chain Compromise"],
            auth_level_required=AuthorizationLevel.AGGRESSIVE,
            cwe_ids=["CWE-502", "CWE-829", "CWE-506", "CWE-200"],
            tags=["ai", "ml", "supply_chain", "model_loading", "pickle", "serialization"],
        )

    async def _get_payloads(self, target: str, options: dict[str, Any]) -> list[str]:
        """Get supply chain probing paths from database or defaults."""
        if self._payload_db:
            db_payloads = await self._payload_db.get_payloads("ai_supply_chain", limit=300)
            if db_payloads:
                return db_payloads
        return DEFAULT_SUPPLY_CHAIN_PAYLOADS

    def _build_requests(
        self, target: str, payloads: list[str], options: dict[str, Any]
    ) -> list[AttackRequest]:
        """Build supply-chain discovery requests.

        Uses GET for discovery/enumeration paths and HEAD for model artifact files.
        Uses POST for upload/import endpoints to test serialization attack surfaces.
        """
        requests: list[AttackRequest] = []
        timeout = options.get("timeout", 20.0)

        # Additional auth headers if provided
        base_headers: dict[str, str] = {}
        auth_token = options.get("auth_token", "")
        if auth_token:
            base_headers["Authorization"] = f"Bearer {auth_token}"

        for path in payloads:
            req_id = f"supply-{uuid.uuid4().hex[:8]}"

            # Determine method based on path category
            if path in SERIALIZATION_PATHS:
                # POST to upload endpoints to test if they accept unsafe formats
                for content_type in [
                    "application/octet-stream",
                    "multipart/form-data",
                    "application/x-python-pickle",
                ]:
                    headers = {**base_headers, "Content-Type": content_type}
                    # Send a minimal probe body (not a real pickle/model)
                    probe_body = b"BAS_SUPPLY_CHAIN_PROBE"

                    requests.append(
                        AttackRequest(
                            request_id=f"{req_id}-{content_type.split('/')[-1][:8]}",
                            target=target,
                            method="POST",
                            path=path,
                            body=probe_body,
                            content_type=content_type,
                            headers=headers,
                            timeout=timeout,
                        )
                    )
            elif any(
                path.endswith(ext)
                for ext in (
                    ".pt", ".pth", ".h5", ".keras", ".onnx", ".pb", ".pkl",
                    ".joblib", ".gguf", ".ggml", ".safetensors", ".bin",
                )
            ):
                # HEAD request for model artifact files to check existence
                requests.append(
                    AttackRequest(
                        request_id=req_id,
                        target=target,
                        method="HEAD",
                        path=path,
                        headers=base_headers,
                        timeout=timeout,
                        follow_redirects=True,
                    )
                )
                # Also try GET with range header for partial download confirmation
                range_headers = {**base_headers, "Range": "bytes=0-127"}
                requests.append(
                    AttackRequest(
                        request_id=f"{req_id}-range",
                        target=target,
                        method="GET",
                        path=path,
                        headers=range_headers,
                        timeout=timeout,
                        follow_redirects=True,
                    )
                )
            else:
                # GET for all discovery/enumeration paths
                requests.append(
                    AttackRequest(
                        request_id=req_id,
                        target=target,
                        method="GET",
                        path=path,
                        headers={**base_headers, "Accept": "application/json, text/html, */*"},
                        timeout=timeout,
                        follow_redirects=True,
                    )
                )

        return requests

    def _analyze_response(
        self, request: AttackRequest, response: AttackResponse, payload: str
    ) -> ModuleResult:
        """Analyze response for supply chain security issues."""
        if response.error:
            if response.error == "timeout":
                return ModuleResult(
                    module_name="ai_supply_chain",
                    target=request.target,
                    status=VulnStatus.TIMEOUT,
                    payload_used=payload,
                    elapsed_ms=response.elapsed_ms,
                    detail={"error": "timeout"},
                )
            return ModuleResult(
                module_name="ai_supply_chain",
                target=request.target,
                status=VulnStatus.ERROR,
                payload_used=payload,
                elapsed_ms=response.elapsed_ms,
                detail={"error": response.error},
            )

        body = response.body_text
        body_lower = body.lower()
        status_code = response.status_code
        content_type = response.headers.get("content-type", "").lower()
        evidence_parts: list[str] = []
        category = self._classify_path(payload)
        severity = "info"

        # ── 1. Model registry / hosting exposure ─────────────────────────
        if category in ("model_registry", "model_hosting"):
            if status_code == 200:
                registry_hits = [
                    ind for ind in REGISTRY_INDICATORS if ind in body_lower
                ]
                if registry_hits:
                    evidence_parts.append(
                        f"Model registry/hosting exposed: {', '.join(registry_hits)}"
                    )
                    severity = "critical"
                elif len(body) > 50 and "json" in content_type:
                    evidence_parts.append(
                        "Model endpoint returned JSON data (possible model listing)"
                    )
                    severity = "high"

        # ── 2. Cache / storage exposure ──────────────────────────────────
        elif category == "cache_exposure":
            if status_code == 200:
                evidence_parts.append(
                    f"Cache/storage path accessible: {payload}"
                )
                severity = "high"
            elif status_code == 403:
                evidence_parts.append(
                    f"Cache path exists but forbidden (confirms infrastructure): {payload}"
                )
                severity = "medium"

        # ── 3. Serialization upload endpoints ────────────────────────────
        elif category == "serialization":
            if status_code in (200, 201, 202):
                evidence_parts.append(
                    f"Model upload endpoint accepted request: {payload} "
                    f"(Content-Type: {request.content_type})"
                )
                severity = "critical"
            elif status_code == 400:
                # 400 means endpoint exists but rejected our probe - still interesting
                if any(
                    kw in body_lower
                    for kw in ("pickle", "invalid model", "deserialization", "format", "expected")
                ):
                    evidence_parts.append(
                        f"Upload endpoint exists and parses model format: {payload}"
                    )
                    severity = "high"
            elif status_code == 401 or status_code == 403:
                evidence_parts.append(
                    f"Upload endpoint exists (auth required): {payload}"
                )
                severity = "medium"

        # ── 4. Model artifact files ──────────────────────────────────────
        elif category == "model_artifact":
            if status_code == 200 or status_code == 206:
                # Check content-type for binary/model data
                if any(ct in content_type for ct in MODEL_FILE_CONTENT_TYPES):
                    evidence_parts.append(
                        f"Model artifact file exposed: {payload} "
                        f"(Content-Type: {content_type})"
                    )
                    severity = "critical"
                elif len(response.body) > 1000:
                    evidence_parts.append(
                        f"Large file accessible at model path: {payload} "
                        f"({len(response.body)} bytes)"
                    )
                    severity = "high"
            elif status_code == 403:
                evidence_parts.append(
                    f"Model artifact path exists but forbidden: {payload}"
                )
                severity = "low"

        # ── 5. Dependency file exposure ──────────────────────────────────
        elif category == "dependency":
            if status_code == 200 and len(body) > 10:
                dep_hits = [
                    dep for dep in DEPENDENCY_INDICATORS if dep in body_lower
                ]
                vuln_deps = []
                for pattern in VULNERABLE_DEPENDENCY_PATTERNS:
                    matches = pattern.findall(body)
                    if matches:
                        vuln_deps.extend(matches)
                if dep_hits:
                    evidence_parts.append(
                        f"Dependency file exposed: {payload} "
                        f"(ML packages found: {', '.join(dep_hits[:10])})"
                    )
                    severity = "high"
                if vuln_deps:
                    evidence_parts.append(
                        f"Potentially vulnerable dependencies: {', '.join(vuln_deps[:5])}"
                    )
                    severity = "critical"

        # ── 6. Notebook exposure ─────────────────────────────────────────
        elif category == "notebook":
            if status_code == 200:
                nb_hits = [
                    ind for ind in NOTEBOOK_INDICATORS if ind in body_lower
                ]
                if nb_hits:
                    evidence_parts.append(
                        f"Jupyter notebook/lab exposed: {payload} "
                        f"(indicators: {', '.join(nb_hits)})"
                    )
                    severity = "critical"
                elif "jupyter" in body_lower or "ipython" in body_lower:
                    evidence_parts.append(
                        f"Jupyter interface detected: {payload}"
                    )
                    severity = "critical"

        # ── 7. ML pipeline / experiment tracking ─────────────────────────
        elif category == "pipeline":
            if status_code == 200:
                pipeline_hits = [
                    ind for ind in PIPELINE_INDICATORS if ind in body_lower
                ]
                if pipeline_hits:
                    evidence_parts.append(
                        f"ML pipeline/tracking exposed: {payload} "
                        f"(indicators: {', '.join(pipeline_hits)})"
                    )
                    severity = "critical"
                elif "json" in content_type and len(body) > 50:
                    evidence_parts.append(
                        f"Pipeline endpoint returned data: {payload}"
                    )
                    severity = "high"

        # ── Determine final status ───────────────────────────────────────
        if evidence_parts:
            if severity in ("critical", "high"):
                status = VulnStatus.VULNERABLE
            else:
                status = VulnStatus.POTENTIALLY_VULNERABLE
        else:
            status = VulnStatus.NOT_VULNERABLE

        return ModuleResult(
            module_name="ai_supply_chain",
            target=request.target,
            status=status,
            payload_used=payload,
            response_code=status_code,
            response_body_preview=body[:500] if body else "",
            elapsed_ms=response.elapsed_ms,
            evidence="; ".join(evidence_parts) if evidence_parts else "",
            severity=severity if status != VulnStatus.NOT_VULNERABLE else "info",
            mitre_technique_id="T1195",
            detail={
                "path_category": category,
                "content_type": content_type,
                "response_size": len(response.body),
                "headers": dict(response.headers) if response.headers else {},
            },
        )

    # ── Helper methods ───────────────────────────────────────────────────────

    @staticmethod
    def _classify_path(path: str) -> str:
        """Classify a probe path into its category."""
        if path in MODEL_REGISTRY_PATHS:
            return "model_registry"
        if path in MODEL_HOSTING_PATHS:
            return "model_hosting"
        if path in CACHE_EXPOSURE_PATHS:
            return "cache_exposure"
        if path in SERIALIZATION_PATHS:
            return "serialization"
        if path in DEPENDENCY_PATHS:
            return "dependency"
        if path in MODEL_ARTIFACT_PATHS:
            return "model_artifact"
        if path in NOTEBOOK_PATHS:
            return "notebook"
        if path in PIPELINE_PATHS:
            return "pipeline"
        # Fallback heuristics
        for ext in (".pt", ".pth", ".h5", ".onnx", ".pb", ".pkl", ".joblib",
                     ".gguf", ".ggml", ".safetensors", ".bin", ".keras"):
            if path.endswith(ext):
                return "model_artifact"
        if "requirements" in path or "pipfile" in path.lower() or "setup" in path.lower():
            return "dependency"
        if "notebook" in path.lower() or "ipynb" in path.lower() or "jupyter" in path.lower():
            return "notebook"
        return "general"
