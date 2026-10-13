"""Canary listener -- FastAPI webhook that logs trap triggers to the database."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Query
from fastapi.responses import JSONResponse
import uvicorn

from database import record_alert, get_all_traps

# Pre-load valid trap endpoints at startup
_valid_trap_ids: set[str] = set()


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Populate the known trap ID set from the database on startup."""
    global _valid_trap_ids
    traps = get_all_traps()
    _valid_trap_ids = {
        row["endpoint_url"].split("id=")[-1]
        for row in traps
        if "id=" in row["endpoint_url"]
    }
    yield


app = FastAPI(
    title="SpectreSync Canary Listener",
    docs_url=None,   # hide docs from attackers
    redoc_url=None,
    lifespan=lifespan,
)





def _extract_caller(request: Request, trap_id: str) -> dict:
    """Pull caller details from the inbound request."""
    return {
        "ip": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", ""),
        "trap_id": trap_id,
    }


def _resolve_trap_db_id(trap_id: str) -> int | None:
    """Map a trap_id string (e.g. 'trap_01') to the database row id."""
    for row in get_all_traps():
        if row["endpoint_url"].endswith(f"id={trap_id}"):
            return row["id"]
    return None


@app.api_route("/api/canary-hit", methods=["GET", "POST"])
async def canary_hit(
    request: Request,
    id: str = Query(default="", alias="id"),
) -> JSONResponse:
    """Handle a triggered canary trap."""
    caller = _extract_caller(request, id)
    db_trap_id = _resolve_trap_db_id(id)

    if db_trap_id is not None:
        # Silently log the incident
        record_alert(
            trap_id=db_trap_id,
            source_ip=caller["ip"],
            user_agent=caller["user_agent"],
            status="Triggered",
        )

    # Return a convincing fake 404 to keep the decoy believable
    return JSONResponse(
        status_code=404,
        content={"detail": "Not Found"},
    )


@app.get("/health")
async def health() -> dict:
    """Basic liveness probe (internal use only)."""
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)

