"""
Local AI Model Manager.

Manages local LLM instances via Ollama or llama-cpp-python.
Designed for air-gapped / private deployments with no cloud dependencies.

Supported backends:
  - Ollama (recommended for ease of use)
  - llama-cpp-python (for direct GGUF model loading)
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ModelBackend(str, Enum):
    OLLAMA = "ollama"
    LLAMA_CPP = "llama_cpp"


class ModelConfig(BaseModel):
    """Configuration for a local AI model."""

    backend: ModelBackend = ModelBackend.OLLAMA
    model_name: str = Field(default="llama3.2", description="Model identifier")
    model_path: str = Field(default="", description="Path to GGUF file (llama_cpp only)")
    context_length: int = Field(default=8192, ge=512, le=131072)
    temperature: float = Field(default=0.3, ge=0.0, le=2.0)
    top_p: float = Field(default=0.9, ge=0.0, le=1.0)
    max_tokens: int = Field(default=2048, ge=1, le=32768)
    gpu_layers: int = Field(default=-1, description="-1 = auto, 0 = CPU only")
    system_prompt: str = Field(default="", description="System prompt override")

    # Ollama-specific
    ollama_host: str = Field(default="http://localhost:11434")

    # Quantization
    quantization: str = Field(default="Q4_K_M", description="GGUF quantization level")


class ModelBackendInterface(ABC):
    """Abstract interface for model backends."""

    @abstractmethod
    async def generate(self, prompt: str, system: str = "", **kwargs: Any) -> str:
        """Generate a completion."""
        ...

    @abstractmethod
    async def generate_stream(self, prompt: str, system: str = "", **kwargs: Any) -> AsyncIterator[str]:
        """Generate a streaming completion."""
        ...

    @abstractmethod
    async def embed(self, text: str) -> list[float]:
        """Generate embeddings for text."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the backend is available."""
        ...


class OllamaBackend(ModelBackendInterface):
    """Ollama backend for local model inference."""

    def __init__(self, config: ModelConfig):
        self._config = config
        self._client: Any = None

    async def _get_client(self) -> Any:
        if self._client is None:
            try:
                import ollama
                self._client = ollama.AsyncClient(host=self._config.ollama_host)
            except ImportError:
                raise RuntimeError(
                    "ollama package not installed. Install with: pip install ollama"
                )
        return self._client

    async def generate(self, prompt: str, system: str = "", **kwargs: Any) -> str:
        client = await self._get_client()
        messages = []
        if system or self._config.system_prompt:
            messages.append({"role": "system", "content": system or self._config.system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = await client.chat(
            model=self._config.model_name,
            messages=messages,
            options={
                "temperature": kwargs.get("temperature", self._config.temperature),
                "top_p": kwargs.get("top_p", self._config.top_p),
                "num_predict": kwargs.get("max_tokens", self._config.max_tokens),
                "num_ctx": self._config.context_length,
            },
        )
        return response["message"]["content"]

    async def generate_stream(self, prompt: str, system: str = "", **kwargs: Any) -> AsyncIterator[str]:
        client = await self._get_client()
        messages = []
        if system or self._config.system_prompt:
            messages.append({"role": "system", "content": system or self._config.system_prompt})
        messages.append({"role": "user", "content": prompt})

        stream = await client.chat(
            model=self._config.model_name,
            messages=messages,
            stream=True,
            options={
                "temperature": kwargs.get("temperature", self._config.temperature),
                "num_predict": kwargs.get("max_tokens", self._config.max_tokens),
                "num_ctx": self._config.context_length,
            },
        )
        async for chunk in stream:
            yield chunk["message"]["content"]

    async def embed(self, text: str) -> list[float]:
        client = await self._get_client()
        response = await client.embed(
            model=self._config.model_name,
            input=text,
        )
        return response["embeddings"][0]

    async def health_check(self) -> bool:
        try:
            client = await self._get_client()
            await client.list()
            return True
        except Exception:
            return False


class LlamaCppBackend(ModelBackendInterface):
    """llama-cpp-python backend for direct GGUF model loading."""

    def __init__(self, config: ModelConfig):
        self._config = config
        self._model: Any = None

    def _load_model(self) -> Any:
        if self._model is None:
            try:
                from llama_cpp import Llama
            except ImportError:
                raise RuntimeError(
                    "llama-cpp-python not installed. Install with: pip install llama-cpp-python"
                )

            if not self._config.model_path:
                raise ValueError("model_path is required for llama_cpp backend")

            self._model = Llama(
                model_path=self._config.model_path,
                n_ctx=self._config.context_length,
                n_gpu_layers=self._config.gpu_layers,
                verbose=False,
            )
        return self._model

    async def generate(self, prompt: str, system: str = "", **kwargs: Any) -> str:
        model = self._load_model()
        full_prompt = self._format_prompt(prompt, system)

        output = model(
            full_prompt,
            max_tokens=kwargs.get("max_tokens", self._config.max_tokens),
            temperature=kwargs.get("temperature", self._config.temperature),
            top_p=kwargs.get("top_p", self._config.top_p),
            stop=["</s>", "[INST]", "Human:", "User:"],
        )
        return output["choices"][0]["text"].strip()

    async def generate_stream(self, prompt: str, system: str = "", **kwargs: Any) -> AsyncIterator[str]:
        model = self._load_model()
        full_prompt = self._format_prompt(prompt, system)

        for chunk in model(
            full_prompt,
            max_tokens=kwargs.get("max_tokens", self._config.max_tokens),
            temperature=kwargs.get("temperature", self._config.temperature),
            stream=True,
        ):
            token = chunk["choices"][0]["text"]
            if token:
                yield token

    async def embed(self, text: str) -> list[float]:
        model = self._load_model()
        return model.embed(text)

    async def health_check(self) -> bool:
        try:
            self._load_model()
            return True
        except Exception:
            return False

    def _format_prompt(self, prompt: str, system: str = "") -> str:
        sys_text = system or self._config.system_prompt
        if sys_text:
            return f"[INST] <<SYS>>\n{sys_text}\n<</SYS>>\n\n{prompt} [/INST]"
        return f"[INST] {prompt} [/INST]"


class ModelManager:
    """
    Manages local AI model instances.

    Handles model selection, loading, and provides a unified inference
    interface regardless of backend.
    """

    def __init__(self, default_config: ModelConfig | None = None):
        self._config = default_config or ModelConfig()
        self._backends: dict[str, ModelBackendInterface] = {}
        self._default_backend: ModelBackendInterface | None = None

    async def initialize(self, config: ModelConfig | None = None) -> None:
        """Initialize the default model backend."""
        config = config or self._config
        backend = self._create_backend(config)

        if await backend.health_check():
            self._default_backend = backend
            self._backends[config.model_name] = backend
            logger.info(f"Initialized {config.backend.value} backend with model {config.model_name}")
        else:
            logger.warning(f"Backend {config.backend.value} health check failed - operating in offline mode")

    def _create_backend(self, config: ModelConfig) -> ModelBackendInterface:
        if config.backend == ModelBackend.OLLAMA:
            return OllamaBackend(config)
        elif config.backend == ModelBackend.LLAMA_CPP:
            return LlamaCppBackend(config)
        else:
            raise ValueError(f"Unknown backend: {config.backend}")

    async def generate(self, prompt: str, system: str = "", model_name: str = "", **kwargs: Any) -> str:
        """Generate a completion using the specified or default model."""
        backend = self._get_backend(model_name)
        return await backend.generate(prompt, system, **kwargs)

    async def generate_stream(self, prompt: str, system: str = "", model_name: str = "", **kwargs: Any) -> AsyncIterator[str]:
        """Generate a streaming completion."""
        backend = self._get_backend(model_name)
        async for token in backend.generate_stream(prompt, system, **kwargs):
            yield token

    async def embed(self, text: str, model_name: str = "") -> list[float]:
        """Generate embeddings."""
        backend = self._get_backend(model_name)
        return await backend.embed(text)

    def _get_backend(self, model_name: str = "") -> ModelBackendInterface:
        if model_name and model_name in self._backends:
            return self._backends[model_name]
        if self._default_backend:
            return self._default_backend
        raise RuntimeError("No model backend initialized. Call initialize() first.")

    async def list_available_models(self) -> list[dict[str, Any]]:
        """List models available in the backend."""
        if isinstance(self._default_backend, OllamaBackend):
            client = await self._default_backend._get_client()
            response = await client.list()
            return [{"name": m["name"], "size": m.get("size", 0)} for m in response.get("models", [])]
        return [{"name": self._config.model_name, "backend": self._config.backend.value}]
