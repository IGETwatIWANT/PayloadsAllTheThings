"""EDR/WAF/AMSI evasion, traffic shaping, and ransomware simulation modules."""
from bas.modules.evasion.edr_evasion import EDREvasionModule
from bas.modules.evasion.waf_bypass import WAFBypassModule
from bas.modules.evasion.amsi_bypass import AMSIBypassModule
from bas.modules.evasion.traffic_shaping import TrafficShapingModule
from bas.modules.evasion.ransomware_sim import RansomwareSimModule

__all__ = [
    "EDREvasionModule", "WAFBypassModule", "AMSIBypassModule",
    "TrafficShapingModule", "RansomwareSimModule",
]
