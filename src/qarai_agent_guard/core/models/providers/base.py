from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from qarai_agent_guard.core.schemas.models import ModelConfig


class ModelProvider(ABC):
    """Define the provider boundary for lifecycle and raw inference."""

    def __init__(self, config: ModelConfig) -> None:
        self.config = config

    @abstractmethod
    def load(self) -> None: ...

    @abstractmethod
    def predict(self, text: str) -> Any: ...

    @abstractmethod
    def unload(self) -> None: ...
