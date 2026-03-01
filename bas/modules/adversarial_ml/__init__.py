"""
Adversarial ML attack modules for BASzy Ai.
Tests AI/ML system security for authorized red team engagements.
"""
from bas.modules.adversarial_ml.prompt_injection import PromptInjectionModule
from bas.modules.adversarial_ml.model_extraction import ModelExtractionModule
from bas.modules.adversarial_ml.model_evasion import ModelEvasionModule
from bas.modules.adversarial_ml.data_leakage import DataLeakageModule
from bas.modules.adversarial_ml.ai_supply_chain import AISupplyChainModule
from bas.modules.adversarial_ml.ai_dos import AIDosModule

__all__ = [
    "PromptInjectionModule",
    "ModelExtractionModule",
    "ModelEvasionModule",
    "DataLeakageModule",
    "AISupplyChainModule",
    "AIDosModule",
]
