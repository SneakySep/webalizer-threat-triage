"""API v1 router assembly."""

from fastapi import APIRouter, Depends

from app.api.deps import require_api_key
from app.api.v1.endpoints.triage import router as triage_router

api_router = APIRouter()
api_router.include_router(
    triage_router,
    dependencies=[Depends(require_api_key)],
)
