"""EDR/WAF/AMSI evasion and traffic shaping modules for authorized testing."""
from bas.modules.evasion.edr_evasion import EDREvasionModule
from bas.modules.evasion.waf_bypass import WAFBypassModule
from bas.modules.evasion.amsi_bypass import AMSIBypassModule
from bas.modules.evasion.traffic_shaping import TrafficShapingModule

__all__ = ["EDREvasionModule", "WAFBypassModule", "AMSIBypassModule", "TrafficShapingModule"]
