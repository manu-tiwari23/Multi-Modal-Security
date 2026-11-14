from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.threat_intel.models import IndicatorType
from src.threat_intel.runtime import get_threat_intel

router = APIRouter()


class LookupRequest(BaseModel):
    value: str = Field(min_length=1, max_length=4096)
    type: IndicatorType | None = None
    allow_external: bool = False


@router.post("/api/threat-intel/lookup")
def lookup_indicator(body: LookupRequest, service=Depends(get_threat_intel)):
    try:
        return service.lookup(body.value, body.type, body.allow_external).model_dump(mode="json")
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.get("/api/threat-intel/status")
def threat_intel_status(service=Depends(get_threat_intel)):
    return {"providers": [{"name": p.name, "configured": bool(getattr(p, "api_key", "")),
                            "local": bool(getattr(p, "local", False))} for p in service.providers],
            "external_lookup_default": False,
            "notice": "Explicit external lookups disclose the indicator to the configured providers, including possible publication in their datasets."}
