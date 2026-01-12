"""
FastAPI web application for KEV Mapper
"""
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import logging

from ..config import get_config
from ..database import get_db, Match, KEVEntry, Asset, MatchStatus
from ..ingestion import KEVIngestor
from ..ingestion.environment_importer import EnvironmentImporter
from ..matching import MatchingEngine
from ..prioritization import PrioritizationScorer
from ..ai import RemediationAssistant
from ..exports import MarkdownExporter, JSONExporter, CSVExporter

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="KEV Mapper", description="KEV-to-Environment Correlation Agent")

# Setup templates
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# Load config
config = get_config()
db = get_db(config.database.path)


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Home page"""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/stats")
async def get_stats():
    """Get dashboard statistics"""
    with db.get_session() as session:
        total_kevs = session.query(KEVEntry).count()
        total_assets = session.query(Asset).count()
        total_matches = session.query(Match).count()
        open_matches = session.query(Match).filter(Match.status == "open").count()
        mitigated_matches = session.query(Match).filter(Match.status == "mitigated").count()

        return {
            "total_kevs": total_kevs,
            "total_assets": total_assets,
            "total_matches": total_matches,
            "open_matches": open_matches,
            "mitigated_matches": mitigated_matches
        }


@app.get("/api/matches")
async def list_matches(status: str = None, limit: int = 50, offset: int = 0):
    """List matches with pagination"""
    with db.get_session() as session:
        query = session.query(Match)

        if status:
            query = query.filter(Match.status == status)

        # Get total count
        total = query.count()

        # Apply pagination
        matches = query.order_by(Match.priority_score.desc())\
            .limit(limit).offset(offset).all()

        # Serialize matches
        matches_data = []
        for match in matches:
            kev = session.query(KEVEntry).filter_by(id=match.kev_entry_id).first()
            asset = session.query(Asset).filter_by(id=match.asset_id).first()

            if not kev or not asset:
                continue

            matches_data.append({
                "id": match.id,
                "cve_id": kev.cve_id,
                "product": kev.product,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "priority_score": match.priority_score,
                "status": match.status.value if isinstance(match.status, MatchStatus) else match.status,
                "confidence_level": match.confidence_level,
                "created_at": match.created_at.isoformat() if match.created_at else None
            })

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "matches": matches_data
        }


@app.get("/api/matches/{match_id}")
async def get_match(match_id: int):
    """Get detailed information about a specific match"""
    with db.get_session() as session:
        match = session.query(Match).filter_by(id=match_id).first()

        if not match:
            raise HTTPException(status_code=404, detail="Match not found")

        kev = session.query(KEVEntry).filter_by(id=match.kev_entry_id).first()
        asset = session.query(Asset).filter_by(id=match.asset_id).first()

        match_data = {
            "id": match.id,
            "status": match.status.value if isinstance(match.status, MatchStatus) else match.status,
            "priority_score": match.priority_score,
            "confidence_level": match.confidence_level,
            "match_rationale": match.match_rationale,
            "created_at": match.created_at.isoformat() if match.created_at else None,
            "updated_at": match.updated_at.isoformat() if match.updated_at else None,
        }

        if kev:
            match_data["kev_entry"] = {
                "cve_id": kev.cve_id,
                "vendor_project": kev.vendor_project,
                "product": kev.product,
                "vulnerability_name": kev.vulnerability_name,
                "short_description": kev.short_description,
                "required_action": kev.required_action,
                "date_added": kev.date_added.isoformat() if kev.date_added else None,
                "due_date": kev.due_date.isoformat() if kev.due_date else None,
            }

        if asset:
            match_data["asset"] = {
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "operating_system": asset.operating_system,
                "criticality": asset.criticality.value if asset.criticality else None,
                "environment": asset.environment.value if asset.environment else None,
                "exposure": asset.exposure.value if asset.exposure else None,
            }

        if match.remediation_packet:
            match_data["remediation_packet"] = match.remediation_packet

        if match.priority_factors:
            match_data["priority_factors"] = match.priority_factors

        return match_data


@app.post("/api/sync")
async def sync_kev(background_tasks: BackgroundTasks):
    """Trigger KEV sync"""
    def run_sync():
        with db.get_session() as session:
            ingestor = KEVIngestor(config, session)
            result = ingestor.sync()
            logger.info(f"KEV sync completed: {result}")

    background_tasks.add_task(run_sync)
    return {"message": "KEV sync started"}


@app.post("/api/match")
async def run_matching(background_tasks: BackgroundTasks):
    """Trigger matching engine"""
    def run_match():
        with db.get_session() as session:
            engine = MatchingEngine(config, session)
            result = engine.run_matching()
            logger.info(f"Matching completed: {result}")

    background_tasks.add_task(run_match)
    return {"message": "Matching started"}


@app.post("/api/prioritize")
async def run_prioritization(background_tasks: BackgroundTasks):
    """Trigger prioritization"""
    def run_prioritize():
        with db.get_session() as session:
            scorer = PrioritizationScorer(config, session)
            scorer.score_all_matches()
            logger.info("Prioritization completed")

    background_tasks.add_task(run_prioritize)
    return {"message": "Prioritization started"}


@app.post("/api/matches/{match_id}/remediate")
async def generate_remediation(match_id: int, background_tasks: BackgroundTasks):
    """Generate AI remediation packet for a match"""
    with db.get_session() as session:
        match = session.query(Match).filter_by(id=match_id).first()
        if not match:
            raise HTTPException(status_code=404, detail="Match not found")

    def run_remediation():
        with db.get_session() as session:
            assistant = RemediationAssistant(config, session)
            packet = assistant.generate_remediation_packet(match_id)
            logger.info(f"Remediation packet generated for match {match_id}")

    background_tasks.add_task(run_remediation)
    return {"message": "Remediation generation started"}


@app.post("/api/matches/{match_id}/status")
async def update_match_status(match_id: int, status: str, notes: str = None):
    """Update match status"""
    with db.get_session() as session:
        match = session.query(Match).filter_by(id=match_id).first()
        if not match:
            raise HTTPException(status_code=404, detail="Match not found")

        if status == "mitigated":
            engine = MatchingEngine(config, session)
            engine.mark_mitigated(match_id, notes or "")
        elif status == "false_positive":
            engine = MatchingEngine(config, session)
            engine.mark_false_positive(match_id, notes or "")
        else:
            # Update status directly
            match.status = MatchStatus[status.upper()]
            session.commit()

        return {"message": "Status updated successfully"}


@app.get("/api/export/{format}")
async def export_data(format: str, limit: int = 50):
    """Export matches in specified format"""
    with db.get_session() as session:
        matches = session.query(Match).filter(
            Match.status == "open"
        ).order_by(Match.priority_score.desc()).limit(limit).all()

        if not matches:
            raise HTTPException(status_code=404, detail="No matches to export")

        if format == "markdown":
            exporter = MarkdownExporter(session, config.reporting.default_export_path)
            output_path = exporter.export_multiple_matches(matches)
        elif format == "json":
            exporter = JSONExporter(session, config.reporting.default_export_path)
            output_path = exporter.export_work_queue(limit)
        elif format == "csv":
            exporter = CSVExporter(session, config.reporting.default_export_path)
            output_path = exporter.export_work_queue(limit)
        else:
            raise HTTPException(status_code=400, detail="Unsupported format")

        return FileResponse(output_path, filename=Path(output_path).name)


@app.get("/matches", response_class=HTMLResponse)
async def matches_page(request: Request):
    """Matches listing page"""
    return templates.TemplateResponse("matches.html", {"request": request})


@app.get("/assets", response_class=HTMLResponse)
async def assets_page(request: Request):
    """Assets listing page"""
    return templates.TemplateResponse("assets.html", {"request": request})


@app.get("/kev", response_class=HTMLResponse)
async def kev_page(request: Request):
    """KEV updates page"""
    return templates.TemplateResponse("kev.html", {"request": request})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
