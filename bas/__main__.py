"""
BASzy Ai CLI - AI-Driven Breach & Attack Simulation Platform
=============================================================

State-of-the-art penetration testing powered by local AI.

Usage:
    baszy scan <target> [--modules ...] [--config ...]
    baszy attack <target> --module <module> [--payloads ...]
    baszy recon <target>
    baszy plan <target> [--objectives ...]
    baszy report <engagement_id>
    baszy payloads list [--category ...]
    baszy payloads load
    baszy gui [--port 8443]
    baszy config init
    baszy models list
"""

from __future__ import annotations

import asyncio
import logging
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.tree import Tree
from rich import box

app = typer.Typer(
    name="baszy",
    help="BASzy Ai - AI-Driven Breach and Attack Simulation Platform",
    no_args_is_help=True,
)
console = Console()

# ─── Banner ──────────────────────────────────────────────────────────

BANNER = """
[bold red]
 ██████╗  █████╗ ███████╗███████╗██╗   ██╗     █████╗ ██╗
 ██╔══██╗██╔══██╗██╔════╝╚══███╔╝╚██╗ ██╔╝    ██╔══██╗██║
 ██████╔╝███████║███████╗  ███╔╝  ╚████╔╝     ███████║██║
 ██╔══██╗██╔══██║╚════██║ ███╔╝    ╚██╔╝      ██╔══██║██║
 ██████╔╝██║  ██║███████║███████╗   ██║       ██║  ██║██║
 ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝       ╚═╝  ╚═╝╚═╝
[/bold red]
[dim]AI-Driven Breach & Attack Simulation Platform v1.0.0[/dim]
[dim]Proprietary - Authorized Red Team Operations Only[/dim]
"""


def show_banner():
    console.print(BANNER)


# ─── All Module Names ────────────────────────────────────────────────

ALL_MODULE_NAMES = [
    # Recon (original)
    "discovery",
    # Injection (original)
    "sqli", "xss", "command_injection", "ssti",
    # SSRF (original)
    "ssrf",
    # Auth (original)
    "jwt", "auth_bypass",
    # Web (Phase 2)
    "xxe", "deserialization", "open_redirect", "cors", "crlf",
    "path_traversal", "prototype_pollution", "file_upload",
    "idor", "csrf", "cache_deception", "request_smuggling",
    "graphql", "websocket", "nosqli", "ldap", "xpath", "hpp",
    # Network (Phase 2)
    "port_scan", "dir_brute", "subdomain_enum", "credential_test",
    # Evasion (Phase 2)
    "edr_evasion", "waf_bypass", "amsi_bypass", "traffic_shaping",
    # Advanced (Phase 3)
    "dns_rebinding", "race_condition", "http2_smuggling",
    "jwt_advanced", "api_abuse", "ssi_injection",
    # Infrastructure (Phase 3)
    "cloud_metadata", "container_escape", "secrets_scanner",
    "subdomain_takeover", "api_key_leak", "misconfig_scanner",
    # Post-Exploitation (Phase 3)
    "data_exfil", "privilege_escalation", "session_attacks",
    "password_policy", "email_injection", "business_logic",
    # Recon (Phase 5)
    "osint", "humint",
    # Adversarial ML (Phase 4)
    "prompt_injection", "model_extraction", "model_evasion",
    "data_leakage", "ai_supply_chain", "ai_dos",
    # Auth (Phase 5)
    "mfa_bypass", "credential_phishing",
    # Network (Phase 5)
    "wifi_security", "mitm_assessment", "protocol_exploit",
    # Evasion (Phase 5)
    "ransomware_sim",
]


# ─── Scan Command (Full Assessment) ─────────────────────────────────

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL (e.g., https://target.internal:8443)"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Config file path"),
    modules: Optional[str] = typer.Option(None, "--modules", "-m", help="Comma-separated module list"),
    auth_level: str = typer.Option("low_impact", "--auth-level", "-a", help="Authorization level"),
    authorized_by: str = typer.Option("", "--authorized-by", help="Who authorized this test"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Log actions without executing"),
    max_rps: int = typer.Option(10, "--max-rps", help="Max requests per second"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)"),
    output: str = typer.Option("./bas_output", "--output", "-o", help="Output directory"),
    enable_zeroday: bool = typer.Option(False, "--zeroday", help="Enable AI zero-day simulation"),
    enable_evasion: bool = typer.Option(False, "--evasion", help="Enable EDR/WAF evasion techniques"),
    ai_model: str = typer.Option("llama3.2", "--ai-model", help="AI model name"),
    ai_host: str = typer.Option("http://localhost:11434", "--ai-host", help="Ollama host"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Run a full BASzy Ai scan against a target. This is the main attack command."""
    show_banner()

    if not authorized_by:
        console.print("[bold red]ERROR:[/bold red] --authorized-by is required. Who authorized this assessment?")
        raise typer.Exit(1)

    # Confirmation
    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Auth Level:[/bold] {auth_level}\n"
        f"[bold]Authorized By:[/bold] {authorized_by}\n"
        f"[bold]Dry Run:[/bold] {dry_run}\n"
        f"[bold]Zero-Day:[/bold] {enable_zeroday}\n"
        f"[bold]Evasion:[/bold] {enable_evasion}",
        title="[bold yellow]BASzy Ai Engagement Configuration[/bold yellow]",
        border_style="yellow",
    ))

    if not dry_run:
        confirm = typer.confirm("Proceed with this engagement?")
        if not confirm:
            console.print("[yellow]Engagement cancelled.[/yellow]")
            raise typer.Exit(0)

    asyncio.run(_run_scan(
        target=target,
        config_path=config,
        modules_str=modules,
        auth_level=auth_level,
        authorized_by=authorized_by,
        dry_run=dry_run,
        max_rps=max_rps,
        proxy=proxy,
        output_dir=output,
        enable_zeroday=enable_zeroday,
        enable_evasion=enable_evasion,
        ai_model=ai_model,
        ai_host=ai_host,
        verbose=verbose,
    ))


async def _run_scan(
    target: str,
    config_path: str | None,
    modules_str: str | None,
    auth_level: str,
    authorized_by: str,
    dry_run: bool,
    max_rps: int,
    proxy: str | None,
    output_dir: str,
    enable_zeroday: bool,
    enable_evasion: bool,
    ai_model: str,
    ai_host: str,
    verbose: bool,
):
    """Execute the full scan asynchronously."""
    from bas.config.settings import BASSettings, load_config
    from bas.core.scope import ScopeConfig, AuthorizationLevel
    from bas.core.engine import BASEngine, AttackPhase
    from bas.core.reporter import ReportGenerator, Finding, Severity, EngagementReport
    from bas.ai.model_manager import ModelManager, ModelConfig, ModelBackend
    from bas.ai.planner import AttackPlanner
    from bas.ai.analyzer import ResultAnalyzer
    from bas.payloads.loader import PayloadLoader
    from bas.utils.logging import AuditLogger
    from bas.config.mitre_mapping import get_coverage_matrix

    # Load or build config
    if config_path:
        settings = load_config(config_path)
    else:
        settings = BASSettings(
            targets=[target],
            auth_level=auth_level,
            authorized_by=authorized_by,
            dry_run=dry_run,
            max_rps=max_rps,
            proxy=proxy or "",
            output_dir=output_dir,
            ai_model=ai_model,
            ai_host=ai_host,
            enable_zeroday=enable_zeroday,
        )

    engagement_id = settings.engagement_id or f"BASZY-{uuid.uuid4().hex[:8]}"
    settings.engagement_id = engagement_id

    if modules_str:
        settings.modules = [m.strip() for m in modules_str.split(",")]

    # Setup logging
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    audit = AuditLogger(engagement_id=engagement_id, log_dir=Path(settings.log_dir))

    console.print(f"\n[bold green]Engagement ID:[/bold green] {engagement_id}")
    console.print(f"[bold green]Audit Log:[/bold green] {settings.log_dir}/{engagement_id}.audit.jsonl\n")

    # Initialize AI
    model_config = settings.to_model_config()
    model_manager = ModelManager(model_config)
    ai_available = False

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        # AI Init
        task = progress.add_task("Initializing AI model...", total=None)
        try:
            await model_manager.initialize()
            ai_available = True
            progress.update(task, description="[green]AI model ready")
        except Exception:
            progress.update(task, description="[yellow]AI offline - using heuristic mode")

        # Load payloads
        task = progress.add_task("Loading payload database...", total=None)
        repo_path = Path(settings.repo_path).resolve()
        loader = PayloadLoader(repo_path, settings.payload_db_path)
        db = await loader.load_all()
        stats = await db.get_stats()
        progress.update(task, description=f"[green]Loaded {stats['total_payloads']} payloads from {stats['categories']} categories")

    # Build scope
    scope_config = settings.to_scope_config()
    scope_config.engagement_id = engagement_id

    # Initialize engine
    engine = BASEngine(
        scope_config=scope_config,
        ai_planner=AttackPlanner(model_manager) if ai_available else None,
        audit_logger=audit,
    )

    # Register modules
    analyzer = ResultAnalyzer(model_manager) if ai_available else None
    _register_modules(engine, settings.modules, db, analyzer, model_manager, enable_zeroday, enable_evasion)

    console.print(f"\n[bold]Registered Modules ({len(engine.list_modules())}):[/bold] {', '.join(engine.list_modules())}")

    # Plan attack
    console.print("\n[bold cyan]Phase: Attack Planning[/bold cyan]")
    plan = await engine.plan_attack(
        objectives=["Identify all exploitable vulnerabilities"],
        targets=settings.targets,
    )

    # Display plan
    plan_table = Table(title="Attack Plan", box=box.ROUNDED)
    plan_table.add_column("Phase", style="cyan")
    plan_table.add_column("Module", style="green")
    plan_table.add_column("Auth Level", style="yellow")
    plan_table.add_column("MITRE", style="magenta")

    for phase in plan.phases:
        plan_table.add_row(
            phase.name,
            phase.module_name,
            phase.auth_level_required.value,
            ", ".join(getattr(phase, 'mitre_techniques', []) or []),
        )
    console.print(plan_table)

    # Auto-approve for execution
    engine.approve_plan(plan.plan_id)

    # Execute
    console.print("\n[bold cyan]Phase: Execution[/bold cyan]")
    start_time = datetime.now()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Executing attack plan...", total=len(plan.phases))

        events = await engine.execute(plan)
        progress.update(task, completed=len(plan.phases))

    end_time = datetime.now()

    # Process results
    console.print("\n[bold cyan]Phase: Results Analysis[/bold cyan]")

    findings: list[Finding] = []
    for event in events:
        detail = event.detail
        for result in detail.get("results", []):
            finding = Finding(
                finding_id=f"F-{uuid.uuid4().hex[:6]}",
                title=f"{event.module}: {result.get('evidence', 'Finding')[:80]}",
                severity=Severity(result.get("severity", "info")),
                module=event.module,
                target=result.get("target", event.target),
                description=result.get("evidence", ""),
                evidence=result.get("evidence", ""),
                payload=result.get("payload", ""),
            )
            findings.append(finding)

    # Results summary
    results_table = Table(title="Findings Summary", box=box.ROUNDED)
    results_table.add_column("ID", style="dim")
    results_table.add_column("Severity", style="bold")
    results_table.add_column("Module", style="cyan")
    results_table.add_column("Title")

    severity_colors = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}
    for f in sorted(findings, key=lambda x: list(Severity).index(x.severity)):
        color = severity_colors.get(f.severity.value, "white")
        results_table.add_row(f.finding_id, f"[{color}]{f.severity.value.upper()}[/{color}]", f.module, f.title[:60])

    console.print(results_table)

    # Severity counts
    sev_counts = {s.value: 0 for s in Severity}
    for f in findings:
        sev_counts[f.severity.value] += 1

    console.print(Panel(
        f"[red]Critical: {sev_counts['critical']}[/red]  "
        f"[red]High: {sev_counts['high']}[/red]  "
        f"[yellow]Medium: {sev_counts['medium']}[/yellow]  "
        f"[blue]Low: {sev_counts['low']}[/blue]  "
        f"[dim]Info: {sev_counts['info']}[/dim]  "
        f"| Total: {len(findings)}",
        title="Results",
        border_style="green",
    ))

    # MITRE coverage
    coverage = get_coverage_matrix(settings.modules)
    if coverage:
        coverage_tree = Tree("[bold]MITRE ATT&CK Coverage[/bold]")
        for tactic, techniques in coverage.items():
            tactic_branch = coverage_tree.add(f"[cyan]{tactic}[/cyan]")
            for tech in techniques:
                tactic_branch.add(tech)
        console.print(coverage_tree)

    # Generate report
    report = EngagementReport(
        engagement_id=engagement_id,
        engagement_name=settings.engagement_name,
        start_time=start_time,
        end_time=end_time,
        scope_summary={
            "targets": settings.targets,
            "auth_level": settings.auth_level,
            "authorized_by": settings.authorized_by,
        },
        findings=findings,
        modules_executed=settings.modules,
        targets_tested=settings.targets,
        statistics={
            "duration_seconds": (end_time - start_time).total_seconds(),
            "modules_executed": len(settings.modules),
            "total_findings": len(findings),
            "critical_findings": sev_counts["critical"],
            "high_findings": sev_counts["high"],
        },
    )

    # AI enrichment
    if ai_available and findings:
        reporter = ReportGenerator(ai_analyzer=analyzer)
        report = await reporter.enrich_with_ai(report)
    else:
        reporter = ReportGenerator()

    # Save reports
    output_path = Path(output_dir)
    saved = reporter.save_report(report, output_path)
    for path in saved:
        console.print(f"[green]Report saved:[/green] {path}")

    # Audit verification
    valid, count = audit.verify_chain()
    console.print(f"\n[dim]Audit log: {count} entries, chain integrity: {'VALID' if valid else 'INVALID'}[/dim]")
    console.print(f"[bold green]Engagement {engagement_id} complete.[/bold green]\n")

    await db.close()


def _register_modules(engine, module_names, db, analyzer, model_manager, enable_zeroday, enable_evasion=False):
    """Register attack modules with the engine."""
    # Original modules
    from bas.modules.injection.sqli import SQLInjectionModule
    from bas.modules.injection.xss import XSSModule
    from bas.modules.injection.command_injection import CommandInjectionModule
    from bas.modules.injection.ssti import SSTIModule
    from bas.modules.ssrf.ssrf import SSRFModule
    from bas.modules.auth.jwt import JWTModule
    from bas.modules.auth.auth_bypass import AuthBypassModule
    from bas.modules.recon.discovery import DiscoveryModule

    # Web modules
    from bas.modules.web.xxe import XXEModule
    from bas.modules.web.deserialization import DeserializationModule
    from bas.modules.web.open_redirect import OpenRedirectModule
    from bas.modules.web.cors import CORSModule
    from bas.modules.web.crlf import CRLFModule
    from bas.modules.web.path_traversal import PathTraversalModule
    from bas.modules.web.prototype_pollution import PrototypePollutionModule
    from bas.modules.web.file_upload import FileUploadModule
    from bas.modules.web.idor import IDORModule
    from bas.modules.web.csrf import CSRFModule
    from bas.modules.web.cache_deception import CacheDeceptionModule
    from bas.modules.web.request_smuggling import RequestSmugglingModule
    from bas.modules.web.graphql import GraphQLModule
    from bas.modules.web.websocket import WebSocketModule
    from bas.modules.web.nosqli import NoSQLiModule
    from bas.modules.web.ldap import LDAPiModule
    from bas.modules.web.xpath import XPathiModule
    from bas.modules.web.hpp import HPPModule

    # Network modules
    from bas.modules.network.port_scanner import PortScannerModule
    from bas.modules.network.directory_brute import DirectoryBruteModule
    from bas.modules.network.subdomain_enum import SubdomainEnumModule
    from bas.modules.network.credential_tester import CredentialTesterModule

    # Advanced modules
    from bas.modules.advanced.dns_rebinding import DNSRebindingModule
    from bas.modules.advanced.race_condition import RaceConditionModule
    from bas.modules.advanced.http2_smuggling import HTTP2SmugglingModule
    from bas.modules.advanced.jwt_advanced import JWTAdvancedModule
    from bas.modules.advanced.api_abuse import APIAbuseModule
    from bas.modules.advanced.ssi_injection import SSIInjectionModule

    # Infrastructure modules
    from bas.modules.infrastructure.cloud_metadata import CloudMetadataModule
    from bas.modules.infrastructure.container_escape import ContainerEscapeModule
    from bas.modules.infrastructure.secrets_scanner import SecretsScanner
    from bas.modules.infrastructure.subdomain_takeover import SubdomainTakeoverModule
    from bas.modules.infrastructure.api_key_leak import APIKeyLeakModule
    from bas.modules.infrastructure.misconfig_scanner import MisconfigScanner

    # Post-exploitation modules
    from bas.modules.postexploit.data_exfil import DataExfilModule
    from bas.modules.postexploit.privilege_escalation import PrivilegeEscalationModule
    from bas.modules.postexploit.session_attacks import SessionAttacksModule
    from bas.modules.postexploit.password_policy import PasswordPolicyModule
    from bas.modules.postexploit.email_injection import EmailInjectionModule
    from bas.modules.postexploit.business_logic import BusinessLogicModule

    # Recon modules (Phase 4-5)
    from bas.modules.recon.osint import OSINTModule
    from bas.modules.recon.humint import HUMINTModule

    # Auth modules (Phase 5)
    from bas.modules.auth.mfa_bypass import MFABypassModule
    from bas.modules.auth.credential_phishing import CredentialPhishingModule

    # Network modules (Phase 5)
    from bas.modules.network.wifi_security import WiFiSecurityModule
    from bas.modules.network.mitm_assessment import MitmAssessmentModule
    from bas.modules.network.protocol_exploit import ProtocolExploitModule

    # Evasion modules (Phase 5)
    from bas.modules.evasion.ransomware_sim import RansomwareSimModule

    # Adversarial ML modules
    from bas.modules.adversarial_ml.prompt_injection import PromptInjectionModule
    from bas.modules.adversarial_ml.model_extraction import ModelExtractionModule
    from bas.modules.adversarial_ml.model_evasion import ModelEvasionModule
    from bas.modules.adversarial_ml.data_leakage import DataLeakageModule
    from bas.modules.adversarial_ml.ai_supply_chain import AISupplyChainModule
    from bas.modules.adversarial_ml.ai_dos import AIDosModule

    module_map = {
        # Original
        "discovery": DiscoveryModule,
        "sqli": SQLInjectionModule,
        "xss": XSSModule,
        "command_injection": CommandInjectionModule,
        "ssti": SSTIModule,
        "ssrf": SSRFModule,
        "jwt": JWTModule,
        "auth_bypass": AuthBypassModule,
        # Web
        "xxe": XXEModule,
        "deserialization": DeserializationModule,
        "open_redirect": OpenRedirectModule,
        "cors": CORSModule,
        "crlf": CRLFModule,
        "path_traversal": PathTraversalModule,
        "prototype_pollution": PrototypePollutionModule,
        "file_upload": FileUploadModule,
        "idor": IDORModule,
        "csrf": CSRFModule,
        "cache_deception": CacheDeceptionModule,
        "request_smuggling": RequestSmugglingModule,
        "graphql": GraphQLModule,
        "websocket": WebSocketModule,
        "nosqli": NoSQLiModule,
        "ldap": LDAPiModule,
        "xpath": XPathiModule,
        "hpp": HPPModule,
        # Network
        "port_scan": PortScannerModule,
        "dir_brute": DirectoryBruteModule,
        "subdomain_enum": SubdomainEnumModule,
        "credential_test": CredentialTesterModule,
        # Advanced
        "dns_rebinding": DNSRebindingModule,
        "race_condition": RaceConditionModule,
        "http2_smuggling": HTTP2SmugglingModule,
        "jwt_advanced": JWTAdvancedModule,
        "api_abuse": APIAbuseModule,
        "ssi_injection": SSIInjectionModule,
        # Infrastructure
        "cloud_metadata": CloudMetadataModule,
        "container_escape": ContainerEscapeModule,
        "secrets_scanner": SecretsScanner,
        "subdomain_takeover": SubdomainTakeoverModule,
        "api_key_leak": APIKeyLeakModule,
        "misconfig_scanner": MisconfigScanner,
        # Post-Exploitation
        "data_exfil": DataExfilModule,
        "privilege_escalation": PrivilegeEscalationModule,
        "session_attacks": SessionAttacksModule,
        "password_policy": PasswordPolicyModule,
        "email_injection": EmailInjectionModule,
        "business_logic": BusinessLogicModule,
        # OSINT
        "osint": OSINTModule,
        "humint": HUMINTModule,
        # Adversarial ML
        "prompt_injection": PromptInjectionModule,
        "model_extraction": ModelExtractionModule,
        "model_evasion": ModelEvasionModule,
        "data_leakage": DataLeakageModule,
        "ai_supply_chain": AISupplyChainModule,
        "ai_dos": AIDosModule,
        # Auth (Phase 5)
        "mfa_bypass": MFABypassModule,
        "credential_phishing": CredentialPhishingModule,
        # Network (Phase 5)
        "wifi_security": WiFiSecurityModule,
        "mitm_assessment": MitmAssessmentModule,
        "protocol_exploit": ProtocolExploitModule,
        # Evasion (Phase 5)
        "ransomware_sim": RansomwareSimModule,
    }

    for name in module_names:
        if name in module_map:
            engine.register_module(name, module_map[name](payload_db=db, ai_analyzer=analyzer))

    if enable_zeroday:
        from bas.modules.zeroday.simulator import ZeroDaySimulator
        engine.register_module("zeroday", ZeroDaySimulator(model_manager, payload_db=db, ai_analyzer=analyzer))

    if enable_evasion:
        try:
            from bas.modules.evasion.edr_evasion import EDREvasionModule
            from bas.modules.evasion.waf_bypass import WAFBypassModule
            from bas.modules.evasion.amsi_bypass import AMSIBypassModule
            from bas.modules.evasion.traffic_shaping import TrafficShapingModule
            engine.register_module("edr_evasion", EDREvasionModule(payload_db=db, ai_analyzer=analyzer))
            engine.register_module("waf_bypass", WAFBypassModule(payload_db=db, ai_analyzer=analyzer))
            engine.register_module("amsi_bypass", AMSIBypassModule(payload_db=db, ai_analyzer=analyzer))
            engine.register_module("traffic_shaping", TrafficShapingModule(payload_db=db, ai_analyzer=analyzer))
        except ImportError:
            pass


# ─── Recon Command (Quick Recon) ────────────────────────────────────

@app.command()
def recon(
    target: str = typer.Argument(..., help="Target URL"),
    authorized_by: str = typer.Option(..., "--authorized-by", help="Who authorized this test"),
    output: str = typer.Option("./bas_output", "--output", "-o"),
):
    """Quick reconnaissance scan against a target."""
    show_banner()
    console.print(f"[bold]Running recon against:[/bold] {target}")
    asyncio.run(_run_scan(
        target=target,
        config_path=None,
        modules_str="discovery,port_scan,dir_brute,subdomain_enum",
        auth_level="read_only",
        authorized_by=authorized_by,
        dry_run=False,
        max_rps=5,
        proxy=None,
        output_dir=output,
        enable_zeroday=False,
        enable_evasion=False,
        ai_model="llama3.2",
        ai_host="http://localhost:11434",
        verbose=False,
    ))


# ─── GUI Command ────────────────────────────────────────────────────

@app.command("gui")
def launch_gui(
    host: str = typer.Option("127.0.0.1", "--host", help="GUI bind address"),
    port: int = typer.Option(8443, "--port", "-p", help="GUI port"),
):
    """Launch the BASzy Ai web dashboard."""
    show_banner()
    console.print(f"[bold green]Starting BASzy Ai Dashboard[/bold green]")
    console.print(f"[bold]URL:[/bold] http://{host}:{port}")
    console.print(f"[dim]Press Ctrl+C to stop[/dim]\n")

    import uvicorn
    from bas.api.server import create_app

    api_app = create_app()
    uvicorn.run(api_app, host=host, port=port, log_level="info")


# ─── Payloads Command ───────────────────────────────────────────────

payloads_app = typer.Typer(help="Manage payload database")
app.add_typer(payloads_app, name="payloads")


@payloads_app.command("load")
def payloads_load(
    repo_path: str = typer.Option(".", "--repo", "-r", help="Path to PayloadsAllTheThings repo"),
    db_path: str = typer.Option("./bas_data/payloads.db", "--db", help="Database output path"),
):
    """Parse and load PayloadsAllTheThings into the payload database."""
    show_banner()
    asyncio.run(_load_payloads(repo_path, db_path))


async def _load_payloads(repo_path: str, db_path: str):
    from bas.payloads.loader import PayloadLoader

    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Loading payloads...", total=None)
        loader = PayloadLoader(repo_path, db_path)
        db = await loader.load_all()
        stats = await db.get_stats()
        progress.update(task, description=f"[green]Done!")

    stats_table = Table(title="Payload Database Stats", box=box.ROUNDED)
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Count", style="green", justify="right")
    for key, value in stats.items():
        stats_table.add_row(key, str(value))
    console.print(stats_table)

    categories = await db.get_categories()
    cat_table = Table(title="Categories", box=box.ROUNDED)
    cat_table.add_column("Category", style="cyan")
    cat_table.add_column("Name")
    cat_table.add_column("Total Payloads", justify="right", style="green")
    for cat in categories:
        cat_table.add_row(cat["canonical_name"], cat["name"], str(cat["total_payloads"]))
    console.print(cat_table)

    await db.close()
    console.print(f"\n[green]Database saved to:[/green] {db_path}")


@payloads_app.command("search")
def payloads_search(
    query: str = typer.Argument(..., help="Search query"),
    db_path: str = typer.Option("./bas_data/payloads.db", "--db"),
    limit: int = typer.Option(20, "--limit", "-n"),
):
    """Search the payload database."""
    asyncio.run(_search_payloads(query, db_path, limit))


async def _search_payloads(query: str, db_path: str, limit: int):
    from bas.payloads.database import PayloadDatabase
    async with PayloadDatabase(db_path) as db:
        results = await db.search_payloads(query, limit=limit)

    table = Table(title=f"Search: '{query}'", box=box.ROUNDED)
    table.add_column("Category", style="cyan")
    table.add_column("Payload")
    table.add_column("Source", style="dim")
    for r in results:
        table.add_row(r["category"], r["payload"][:80], r["source"][:30])
    console.print(table)


# ─── Config Command ─────────────────────────────────────────────────

@app.command("init")
def config_init(
    output: str = typer.Option("./baszy_config.yaml", "--output", "-o"),
):
    """Generate a default configuration file."""
    import shutil
    src = Path(__file__).parent / "config" / "default_config.yaml"
    dst = Path(output)
    if dst.exists():
        console.print(f"[yellow]Config already exists:[/yellow] {dst}")
        if not typer.confirm("Overwrite?"):
            raise typer.Exit(0)
    shutil.copy(src, dst)
    console.print(f"[green]Config created:[/green] {dst}")
    console.print("Edit this file with your engagement details, then run: baszy scan <target> --config baszy_config.yaml")


# ─── Models Command ─────────────────────────────────────────────────

@app.command("models")
def models_list(
    ai_host: str = typer.Option("http://localhost:11434", "--host"),
):
    """List available AI models."""
    asyncio.run(_list_models(ai_host))


async def _list_models(host: str):
    from bas.ai.model_manager import ModelManager, ModelConfig
    config = ModelConfig(ollama_host=host)
    mgr = ModelManager(config)
    await mgr.initialize()
    models = await mgr.list_available_models()

    table = Table(title="Available AI Models", box=box.ROUNDED)
    table.add_column("Model", style="cyan")
    table.add_column("Size", justify="right")
    for m in models:
        size_mb = m.get("size", 0) / (1024 * 1024) if m.get("size") else 0
        table.add_row(m["name"], f"{size_mb:.0f} MB" if size_mb else "N/A")
    console.print(table)


# ─── Modules Command ────────────────────────────────────────────────

@app.command("modules")
def list_modules():
    """List all available attack modules."""
    show_banner()
    table = Table(title=f"BASzy Ai Attack Modules ({len(ALL_MODULE_NAMES)})", box=box.ROUNDED)
    table.add_column("#", style="dim", justify="right")
    table.add_column("Module", style="cyan")
    table.add_column("Category", style="green")

    categories = {
        "discovery": "Recon", "port_scan": "Network", "dir_brute": "Network",
        "subdomain_enum": "Network", "credential_test": "Network",
        "sqli": "Injection", "xss": "Injection", "command_injection": "Injection",
        "ssti": "Injection", "nosqli": "Injection", "ldap": "Injection",
        "xpath": "Injection", "ssi_injection": "Injection",
        "ssrf": "SSRF", "jwt": "Auth", "jwt_advanced": "Auth",
        "auth_bypass": "Auth", "xxe": "Web", "deserialization": "Web",
        "open_redirect": "Web", "cors": "Web", "crlf": "Web",
        "path_traversal": "Web", "prototype_pollution": "Web",
        "file_upload": "Web", "idor": "Web", "csrf": "Web",
        "cache_deception": "Web", "request_smuggling": "Web",
        "graphql": "Web", "websocket": "Web", "hpp": "Web",
        "edr_evasion": "Evasion", "waf_bypass": "Evasion",
        "amsi_bypass": "Evasion", "traffic_shaping": "Evasion",
        "dns_rebinding": "Advanced", "race_condition": "Advanced",
        "http2_smuggling": "Advanced", "api_abuse": "Advanced",
        "cloud_metadata": "Infrastructure", "container_escape": "Infrastructure",
        "secrets_scanner": "Infrastructure", "subdomain_takeover": "Infrastructure",
        "api_key_leak": "Infrastructure", "misconfig_scanner": "Infrastructure",
        "data_exfil": "Post-Exploit", "privilege_escalation": "Post-Exploit",
        "session_attacks": "Post-Exploit", "password_policy": "Post-Exploit",
        "email_injection": "Post-Exploit", "business_logic": "Post-Exploit",
        "osint": "Recon", "humint": "Recon",
        "prompt_injection": "Adversarial ML", "model_extraction": "Adversarial ML",
        "model_evasion": "Adversarial ML", "data_leakage": "Adversarial ML",
        "ai_supply_chain": "Adversarial ML", "ai_dos": "Adversarial ML",
        "mfa_bypass": "Auth", "credential_phishing": "Auth",
        "wifi_security": "Network", "mitm_assessment": "Network",
        "protocol_exploit": "Network",
        "ransomware_sim": "Evasion",
    }

    for i, name in enumerate(ALL_MODULE_NAMES, 1):
        table.add_row(str(i), name, categories.get(name, "Other"))
    console.print(table)


# ─── Version ─────────────────────────────────────────────────────────

@app.command("version")
def version():
    """Show BASzy Ai version."""
    from bas import __version__
    console.print(f"BASzy Ai v{__version__}")


# ─── Entry Point ─────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
