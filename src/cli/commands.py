"""
CLI commands for KEV Mapper
"""
import click
import logging
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from pathlib import Path

from ..config import get_config
from ..database import get_db, MatchStatus
from ..ingestion import KEVIngestor
from ..ingestion.environment_importer import EnvironmentImporter
from ..matching import MatchingEngine
from ..prioritization import PrioritizationScorer
from ..ai import RemediationAssistant
from ..exports import MarkdownExporter, JSONExporter, CSVExporter

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

console = Console()


@click.group()
@click.option('--config', default='config.yaml', help='Path to configuration file')
@click.pass_context
def cli(ctx, config):
    """KEV Mapper - KEV-to-Environment Correlation Agent"""
    ctx.ensure_object(dict)
    ctx.obj['config_path'] = config
    ctx.obj['config'] = get_config(config)


@cli.command()
@click.pass_context
def sync(ctx):
    """Sync KEV catalog from CISA"""
    config = ctx.obj['config']
    db = get_db(config.database.path)

    with db.get_session() as session:
        ingestor = KEVIngestor(config, session)

        console.print("[bold blue]Syncing KEV catalog...[/bold blue]")

        try:
            result = ingestor.sync()

            if result["status"] == "unchanged":
                console.print("[yellow]KEV catalog unchanged since last sync[/yellow]")
            else:
                console.print(f"[green]✓ KEV sync completed successfully[/green]")
                console.print(f"  Total entries: {result['entry_count']}")
                console.print(f"  New entries: {len(result.get('new_entries', []))}")
                console.print(f"  Updated entries: {len(result.get('updated_entries', []))}")

                if result.get('new_entries'):
                    console.print(f"\n[bold]New KEV entries:[/bold]")
                    for cve in result['new_entries'][:10]:
                        console.print(f"  - {cve}")
                    if len(result['new_entries']) > 10:
                        console.print(f"  ... and {len(result['new_entries']) - 10} more")

        except Exception as e:
            console.print(f"[red]✗ KEV sync failed: {e}[/red]")
            raise click.Abort()


@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--type', 'source_type', required=True,
              type=click.Choice(['nessus_csv', 'qualys_csv', 'asset_inventory', 'sbom']),
              help='Type of import file')
@click.pass_context
def import_data(ctx, file_path, source_type):
    """Import environment data from scanner or inventory files"""
    config = ctx.obj['config']
    db = get_db(config.database.path)

    with db.get_session() as session:
        importer = EnvironmentImporter(config, session)

        console.print(f"[bold blue]Importing {source_type} from {file_path}...[/bold blue]")

        try:
            result = importer.import_file(file_path, source_type)

            console.print(f"[green]✓ Import completed successfully[/green]")
            if 'findings_imported' in result:
                console.print(f"  Findings imported: {result['findings_imported']}")
            if 'assets_created' in result or 'assets_imported' in result:
                count = result.get('assets_created', result.get('assets_imported', 0))
                console.print(f"  Assets: {count}")

        except Exception as e:
            console.print(f"[red]✗ Import failed: {e}[/red]")
            raise click.Abort()


@cli.command()
@click.option('--cve', multiple=True, help='Specific CVE IDs to match')
@click.pass_context
def match(ctx, cve):
    """Run matching engine to correlate KEV entries with environment"""
    config = ctx.obj['config']
    db = get_db(config.database.path)

    with db.get_session() as session:
        engine = MatchingEngine(config, session)

        console.print("[bold blue]Running KEV matching engine...[/bold blue]")

        try:
            cve_list = list(cve) if cve else None
            result = engine.run_matching(cve_list)

            console.print(f"[green]✓ Matching completed successfully[/green]")
            console.print(f"  KEV entries processed: {result['kev_entries_processed']}")
            console.print(f"  New matches: {result['matches_created']}")
            console.print(f"  Updated matches: {result['matches_updated']}")

        except Exception as e:
            console.print(f"[red]✗ Matching failed: {e}[/red]")
            raise click.Abort()


@cli.command()
@click.pass_context
def prioritize(ctx):
    """Calculate priority scores for all open matches"""
    config = ctx.obj['config']
    db = get_db(config.database.path)

    with db.get_session() as session:
        scorer = PrioritizationScorer(config, session)

        console.print("[bold blue]Calculating priority scores...[/bold blue]")

        try:
            scorer.score_all_matches()
            console.print(f"[green]✓ Prioritization completed successfully[/green]")

        except Exception as e:
            console.print(f"[red]✗ Prioritization failed: {e}[/red]")
            raise click.Abort()


@cli.command()
@click.option('--limit', default=20, help='Number of matches to show')
@click.option('--status', type=click.Choice(['open', 'mitigated', 'false_positive']),
              help='Filter by status')
@click.pass_context
def list_matches(ctx, limit, status):
    """List matches with priority scores"""
    config = ctx.obj['config']
    db = get_db(config.database.path)

    from ..database import Match, KEVEntry, Asset

    with db.get_session() as session:
        query = session.query(Match)

        if status:
            query = query.filter(Match.status == status)

        matches = query.order_by(Match.priority_score.desc()).limit(limit).all()

        if not matches:
            console.print("[yellow]No matches found[/yellow]")
            return

        # Create table
        table = Table(title=f"KEV Matches ({len(matches)} items)")
        table.add_column("ID", style="cyan")
        table.add_column("CVE", style="yellow")
        table.add_column("Asset", style="green")
        table.add_column("Priority", style="magenta")
        table.add_column("Status", style="blue")
        table.add_column("Confidence", style="white")

        for match in matches:
            kev = session.query(KEVEntry).filter_by(id=match.kev_entry_id).first()
            asset = session.query(Asset).filter_by(id=match.asset_id).first()

            if not kev or not asset:
                continue

            priority = f"{match.priority_score:.1f}" if match.priority_score else "N/A"
            status_val = match.status.value if isinstance(match.status, MatchStatus) else match.status

            table.add_row(
                str(match.id),
                kev.cve_id,
                asset.hostname,
                priority,
                status_val,
                match.confidence_level or "N/A"
            )

        console.print(table)


@cli.command()
@click.argument('match_id', type=int)
@click.pass_context
def show(ctx, match_id):
    """Show detailed information about a match"""
    config = ctx.obj['config']
    db = get_db(config.database.path)

    from ..database import Match, KEVEntry, Asset, Finding

    with db.get_session() as session:
        match = session.query(Match).filter_by(id=match_id).first()

        if not match:
            console.print(f"[red]Match {match_id} not found[/red]")
            raise click.Abort()

        kev = session.query(KEVEntry).filter_by(id=match.kev_entry_id).first()
        asset = session.query(Asset).filter_by(id=match.asset_id).first()

        console.print(f"\n[bold]Match #{match.id}[/bold]")
        console.print(f"Status: {match.status.value if isinstance(match.status, MatchStatus) else match.status}")
        console.print(f"Priority Score: {match.priority_score:.1f}/100" if match.priority_score else "Priority Score: N/A")
        console.print(f"Confidence: {match.confidence_level}")

        if kev:
            console.print(f"\n[bold]KEV Entry:[/bold]")
            console.print(f"  CVE: {kev.cve_id}")
            console.print(f"  Product: {kev.vendor_project} {kev.product}")
            console.print(f"  Description: {kev.short_description}")
            console.print(f"  Required Action: {kev.required_action}")

        if asset:
            console.print(f"\n[bold]Asset:[/bold]")
            console.print(f"  Hostname: {asset.hostname}")
            console.print(f"  IP: {asset.ip_address or 'N/A'}")
            console.print(f"  Criticality: {asset.criticality.value if asset.criticality else 'N/A'}")
            console.print(f"  Exposure: {asset.exposure.value if asset.exposure else 'N/A'}")

        console.print(f"\n[bold]Match Details:[/bold]")
        console.print(f"  Rationale: {match.match_rationale}")

        if match.remediation_packet:
            console.print(f"\n[bold]Remediation Packet Available[/bold]")


@cli.command()
@click.argument('match_id', type=int)
@click.pass_context
def remediate(ctx, match_id):
    """Generate AI remediation packet for a match"""
    config = ctx.obj['config']
    db = get_db(config.database.path)

    from ..database import Match

    with db.get_session() as session:
        match = session.query(Match).filter_by(id=match_id).first()

        if not match:
            console.print(f"[red]Match {match_id} not found[/red]")
            raise click.Abort()

        assistant = RemediationAssistant(config, session)

        console.print(f"[bold blue]Generating remediation packet for match {match_id}...[/bold blue]")

        try:
            packet = assistant.generate_remediation_packet(match)

            console.print(f"[green]✓ Remediation packet generated[/green]")

            if 'summary' in packet:
                console.print(f"\n[bold]Summary:[/bold]")
                console.print(packet['summary'])

        except Exception as e:
            console.print(f"[red]✗ Remediation generation failed: {e}[/red]")
            raise click.Abort()


@cli.command()
@click.option('--format', 'output_format', type=click.Choice(['markdown', 'json', 'csv']),
              default='markdown', help='Export format')
@click.option('--limit', default=50, help='Maximum number of matches to export')
@click.option('--output', '-o', help='Output file name')
@click.pass_context
def export(ctx, output_format, limit, output):
    """Export work queue to file"""
    config = ctx.obj['config']
    db = get_db(config.database.path)

    from ..database import Match

    with db.get_session() as session:
        matches = session.query(Match).filter(
            Match.status == "open"
        ).order_by(Match.priority_score.desc()).limit(limit).all()

        if not matches:
            console.print("[yellow]No matches to export[/yellow]")
            return

        console.print(f"[bold blue]Exporting {len(matches)} matches as {output_format}...[/bold blue]")

        try:
            if output_format == 'markdown':
                exporter = MarkdownExporter(session, config.reporting.default_export_path)
                output_path = exporter.export_multiple_matches(matches, output)
            elif output_format == 'json':
                exporter = JSONExporter(session, config.reporting.default_export_path)
                output_path = exporter.export_work_queue(limit, output)
            else:  # csv
                exporter = CSVExporter(session, config.reporting.default_export_path)
                output_path = exporter.export_work_queue(limit, output)

            console.print(f"[green]✓ Exported to {output_path}[/green]")

        except Exception as e:
            console.print(f"[red]✗ Export failed: {e}[/red]")
            raise click.Abort()


@cli.command()
@click.pass_context
def full_sync(ctx):
    """Run complete workflow: sync KEV, match, prioritize"""
    config = ctx.obj['config']
    db = get_db(config.database.path)

    with db.get_session() as session:
        console.print("[bold blue]Running full sync workflow...[/bold blue]\n")

        # Step 1: Sync KEV
        console.print("[1/3] Syncing KEV catalog...")
        ingestor = KEVIngestor(config, session)
        try:
            kev_result = ingestor.sync()
            console.print(f"[green]✓ KEV synced: {kev_result['entry_count']} entries[/green]\n")
        except Exception as e:
            console.print(f"[red]✗ KEV sync failed: {e}[/red]")
            raise click.Abort()

        # Step 2: Match
        console.print("[2/3] Running matching engine...")
        engine = MatchingEngine(config, session)
        try:
            match_result = engine.run_matching()
            console.print(f"[green]✓ Matching complete: {match_result['matches_created']} new matches[/green]\n")
        except Exception as e:
            console.print(f"[red]✗ Matching failed: {e}[/red]")
            raise click.Abort()

        # Step 3: Prioritize
        console.print("[3/3] Calculating priorities...")
        scorer = PrioritizationScorer(config, session)
        try:
            scorer.score_all_matches()
            console.print(f"[green]✓ Prioritization complete[/green]\n")
        except Exception as e:
            console.print(f"[red]✗ Prioritization failed: {e}[/red]")
            raise click.Abort()

        console.print("[bold green]Full sync workflow completed successfully![/bold green]")


if __name__ == '__main__':
    cli(obj={})
