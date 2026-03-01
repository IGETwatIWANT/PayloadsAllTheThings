"""
BAS Engine CLI - Operational Attack Tool
=========================================

Point-and-shoot breach and attack simulation.

Usage:
    bas scan <target> [--modules ...] [--config ...]
    bas attack <target> --module <module> [--payloads ...]
    bas recon <target>
    bas plan <target> [--objectives ...]
    bas report <engagement_id>
    bas payloads list [--category ...]
    bas payloads load
    bas config init
    bas models list
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
    name="bas",
    help="BAS Engine - AI-Driven Breach and Attack Simulation",
    no_args_is_help=True,
)
console = Console()

# ─── Banner ──────────────────────────────────────────────────────────

BANNER = """
[bold red]
 ██████╗  █████╗ ███████╗    ███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗
 ██╔══██╗██╔══██╗██╔════╝    ██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝
 ██████╔╝███████║███████╗    █████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗
 ██╔══██╗██╔══██║╚════██║    ██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝
 ██████╔╝██║  ██║███████║    ███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗
 ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝
[/bold red]
[dim]AI-Driven Breach & Attack Simulation Engine v0.1.0[/dim]
[dim]Authorized Red Team Operations Only[/dim]
"""


def show_banner():
    console.print(BANNER)


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
    ai_model: str = typer.Option("llama3.2", "--ai-model", help="AI model name"),
    ai_host: str = typer.Option("http://localhost:11434", "--ai-host", help="Ollama host"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Run a full BAS scan against a target. This is the main attack command."""
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
        f"[bold]Zero-Day:[/bold] {enable_zeroday}",
        title="[bold yellow]BAS Engagement Configuration[/bold yellow]",
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

    engagement_id = settings.engagement_id or f"BAS-{uuid.uuid4().hex[:8]}"
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
    _register_modules(engine, settings.modules, db, analyzer, model_manager, enable_zeroday)

    console.print(f"\n[bold]Registered Modules:[/bold] {', '.join(engine.list_modules())}")

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


def _register_modules(engine, module_names, db, analyzer, model_manager, enable_zeroday):
    """Register attack modules with the engine."""
    from bas.modules.injection.sqli import SQLInjectionModule
    from bas.modules.injection.xss import XSSModule
    from bas.modules.injection.command_injection import CommandInjectionModule
    from bas.modules.injection.ssti import SSTIModule
    from bas.modules.ssrf.ssrf import SSRFModule
    from bas.modules.auth.jwt import JWTModule
    from bas.modules.auth.auth_bypass import AuthBypassModule
    from bas.modules.recon.discovery import DiscoveryModule

    module_map = {
        "discovery": DiscoveryModule,
        "sqli": SQLInjectionModule,
        "xss": XSSModule,
        "command_injection": CommandInjectionModule,
        "ssti": SSTIModule,
        "ssrf": SSRFModule,
        "jwt": JWTModule,
        "auth_bypass": AuthBypassModule,
    }

    for name in module_names:
        if name in module_map:
            engine.register_module(name, module_map[name](payload_db=db, ai_analyzer=analyzer))

    if enable_zeroday:
        from bas.modules.zeroday.simulator import ZeroDaySimulator
        engine.register_module("zeroday", ZeroDaySimulator(model_manager, payload_db=db, ai_analyzer=analyzer))


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
        modules_str="discovery",
        auth_level="read_only",
        authorized_by=authorized_by,
        dry_run=False,
        max_rps=5,
        proxy=None,
        output_dir=output,
        enable_zeroday=False,
        ai_model="llama3.2",
        ai_host="http://localhost:11434",
        verbose=False,
    ))


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
    output: str = typer.Option("./bas_config.yaml", "--output", "-o"),
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
    console.print("Edit this file with your engagement details, then run: bas scan <target> --config bas_config.yaml")


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


# ─── Version ─────────────────────────────────────────────────────────

@app.command("version")
def version():
    """Show BAS Engine version."""
    from bas import __version__
    console.print(f"BAS Engine v{__version__}")


# ─── Entry Point ─────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
