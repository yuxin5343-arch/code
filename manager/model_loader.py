from __future__ import annotations

from manager.decision_tree import DecisionTreeModel
from manager.rule_engine import RuleEngine


class ModelLoader:
    def __init__(self) -> None:
        self.rule_engine = RuleEngine()
        self.decision_tree = DecisionTreeModel()

    def load_all(self) -> dict:
        return {
            "rule_engine": self.rule_engine,
            "decision_tree": self.decision_tree,
        }

    def load_extended_models(self) -> dict:
        """
        加载扩展后的模型，包括规则引擎和决策树模型的增强功能。
        """
        return {
            "rule_engine": self.rule_engine,
            "decision_tree": self.decision_tree,
            "extended_features": {
                "correlation": self.decision_tree.correlate_alerts,
                "timing_analysis": self.rule_engine.evaluate_with_timing,
            },
        }
