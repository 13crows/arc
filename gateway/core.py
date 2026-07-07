from abc import ABC, abstractmethod
from typing import Dict, Any

class BasePolicyEnforcementPoint(ABC):
    """
    Abstract Base Class for the Policy Enforcement Point (PEP).
    Acts as the contract for all framework-specific interceptors.
    """
    
    @abstractmethod
    def intercept_action(self, framework_context: Any) -> Dict[str, Any]:
        """
        Extracts a normalized action context from a framework-specific payload.
        
        Args:
            framework_context: The raw object/state from LangGraph, AutoGen, etc.
            
        Returns:
            Dict containing normalized fields: resource_type, action, value, data.
        """
        pass

    @abstractmethod
    def enforce(self, framework_context: Any) -> Any:
        """
        Executes the full interception, evaluation, and mitigation loop.
        
        Args:
            framework_context: The raw execution state of the agent.
        """
        pass