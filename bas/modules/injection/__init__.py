"""Injection attack modules - SQLi, XSS, Command Injection, SSTI."""

from bas.modules.injection.sqli import SQLInjectionModule
from bas.modules.injection.xss import XSSModule
from bas.modules.injection.command_injection import CommandInjectionModule
from bas.modules.injection.ssti import SSTIModule

__all__ = ["SQLInjectionModule", "XSSModule", "CommandInjectionModule", "SSTIModule"]
