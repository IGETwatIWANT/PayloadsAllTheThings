"""Digital forensics and incident response modules."""
from bas.modules.forensics.memory_forensics import MemoryForensicsModule
from bas.modules.forensics.disk_forensics import DiskForensicsModule

__all__ = [
    "MemoryForensicsModule",
    "DiskForensicsModule",
]
