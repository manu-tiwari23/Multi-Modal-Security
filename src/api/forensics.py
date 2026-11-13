"""Evidence intake and forensic report workflows orchestrated at the API boundary."""

import asyncio
import base64
import binascii
from urllib.parse import quote
from typing import Awaitable, Callable

from fastapi import APIRouter, HTTPException, Depends
from fastapi.routing import APIRoute
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator

from src.api.reports import ReportFormat, report_response
from src.api.auth import authorize_request, bind_actor
from src.auth.models import Principal
from src.forensics.evidence_vault import EvidenceVault
from src.forensics.file_analyzer import FileAnalyzer
from src.forensics.deleted_recovery import validate_deleted_pair
from src.forensics.integrity_job import IntegrityVerifierJob
from src.forensics.models import EvidenceTamperedError, ChainOfCustodyEntry, CustodyAction, CustodyStatus
from src.forensics.repository import EvidenceStoreUnavailable
from src.forensics.workflows import AnalysisKind, analyze_evidence_bytes
from src.reporting.forensic import build_forensic_report
from src.shared.event_schema import Entity, SecurityEvent
from src.shared.config import settings

MAX_EVIDENCE_BYTES = settings.evidence_max_bytes


class EvidenceUpload(BaseModel):
    filename: str = Field(min_length=1, max_length=240)
    content_base64: str = Field(max_length=4 * ((MAX_EVIDENCE_BYTES + 2) // 3))
    case_id: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_-]+$")
    acquired_by: str | None = Field(default=None, min_length=1, max_length=200)
    source_host: str | None = Field(default=None, max_length=250)

    @field_validator("filename")
    @classmethod
    def plain_filename(cls, value):
        if value in (".", "..") or any(c in value for c in '/\\:\x00') or any(ord(c) < 32 for c in value):
            raise ValueError("Provide a filename, not a filesystem path")
        return value

    @field_validator("acquired_by")
    @classmethod
    def nonblank_actor(cls, value):
        if value is None:
            return value
        if not value.strip():
            raise ValueError("Acquisition identity is required")
        return value.strip()


class DeletedPairRequest(BaseModel):
    metadata_evidence_id: str = Field(min_length=1, max_length=128)
    content_evidence_id: str = Field(min_length=1, max_length=128)


def public_metadata(metadata):
    return metadata.model_dump(mode="json", exclude={"storage_path"})


class ForensicRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        async def storage_errors(request):
            try:
                return await handler(request)
            except EvidenceStoreUnavailable:
                raise HTTPException(503, "Forensic storage unavailable; retry when the storage services are healthy")
        return storage_errors


def create_forensics_router(vault_or_factory, ingest: Callable[[SecurityEvent], Awaitable[dict]]) -> APIRouter:
    router = APIRouter(route_class=ForensicRoute, dependencies=[Depends(authorize_request)])
    def resolve_vault():
        return vault_or_factory() if callable(vault_or_factory) else vault_or_factory
    analyzer = FileAnalyzer()

    async def verified_bytes(vault, evidence_id, actor, purpose):
        try:
            await asyncio.to_thread(vault.get_metadata, evidence_id)
        except KeyError:
            raise HTTPException(404, "Evidence not found")
        events = []
        verifier = IntegrityVerifierJob(vault, event_publisher=events.append)
        integrity = await asyncio.to_thread(verifier.verify_single, evidence_id, actor)
        for event in events:
            await ingest(event)
        if integrity.status != "verified":
            raise HTTPException(409, "Evidence integrity verification failed; analysis halted")
        try:
            data = await asyncio.to_thread(vault.get_evidence_bytes, evidence_id, actor, purpose)
            metadata = await asyncio.to_thread(vault.get_metadata, evidence_id)
            # Historical tamper flags require explicit investigation; replacing bytes must not clear them.
            if metadata.is_tampered:
                raise HTTPException(409, "Evidence is flagged for an integrity investigation")
            return metadata, data
        except KeyError:
            raise HTTPException(404, "Evidence not found")
        except (EvidenceTamperedError, FileNotFoundError) as exc:
            metadata = await asyncio.to_thread(vault.get_metadata, evidence_id)
            await ingest(SecurityEvent(source="forensics", event_type="evidence_tampering_detected" if isinstance(exc, EvidenceTamperedError) else "evidence_missing_detected",
                severity="critical", entity=Entity(hash=metadata.sha256), raw={"evidence_id": evidence_id, "case_id": metadata.case_id}))
            raise HTTPException(409, "Evidence integrity verification failed; analysis halted")

    async def verified_analysis(vault, evidence_id, actor, purpose, kind="file"):
        metadata, data = await verified_bytes(vault, evidence_id, actor, purpose)
        try:
            analysis = await asyncio.to_thread(analyze_evidence_bytes, data, metadata.filename, kind)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        entry = ChainOfCustodyEntry(evidence_id=evidence_id, actor=actor, action=CustodyAction.ANALYZE,
            expected_hash=metadata.sha256, actual_hash=metadata.sha256, status=CustodyStatus.VERIFIED,
            notes=f"Completed {kind} analysis of a verified evidence copy")
        await asyncio.to_thread(vault.record_custody, metadata, entry)
        return metadata, analysis

    @router.post("/api/forensics/evidence", status_code=201)
    async def upload_evidence(body: EvidenceUpload, vault: EvidenceVault = Depends(resolve_vault), principal: Principal = Depends(authorize_request)):
        actor = bind_actor(body.acquired_by, principal)
        try:
            data = base64.b64decode(body.content_base64, validate=True)
        except (ValueError, binascii.Error):
            raise HTTPException(422, "Invalid base64 evidence content")
        if len(data) > MAX_EVIDENCE_BYTES:
            raise HTTPException(413, "Evidence exceeds the configured upload limit")
        metadata = await asyncio.to_thread(vault.ingest_bytes, data, body.filename, actor, body.case_id, body.source_host)
        await ingest(SecurityEvent(source="forensics", event_type="evidence_intake", severity="low",
            entity=Entity(hash=metadata.sha256, host=metadata.source_host),
            raw={"evidence_id": metadata.evidence_id, "case_id": metadata.case_id, "filename": metadata.filename}))
        return public_metadata(metadata)

    @router.get("/api/forensics/evidence")
    def list_evidence(case_id: str | None = None, vault: EvidenceVault = Depends(resolve_vault)):
        items = vault.list_evidence(case_id=case_id)
        return {"total": len(items), "evidence": [public_metadata(m) for m in items]}

    @router.get("/api/forensics/evidence/{evidence_id}")
    def get_evidence(evidence_id: str, vault: EvidenceVault = Depends(resolve_vault)):
        try:
            return public_metadata(vault.get_metadata(evidence_id))
        except KeyError:
            raise HTTPException(404, "Evidence not found")

    @router.post("/api/forensics/evidence/{evidence_id}/analyze")
    async def analyze_evidence(evidence_id: str, kind: AnalysisKind = "file", vault: EvidenceVault = Depends(resolve_vault), principal: Principal = Depends(authorize_request)):
        metadata, analysis = await verified_analysis(vault, evidence_id, principal.username, f"{kind}_analysis", kind)
        return {"evidence": public_metadata(metadata), "analysis_kind": kind, "analysis": analysis}

    @router.post("/api/forensics/evidence/{evidence_id}/verify")
    async def verify_evidence(evidence_id: str, vault: EvidenceVault = Depends(resolve_vault), principal: Principal = Depends(authorize_request)):
        events = []
        try:
            detail = await asyncio.to_thread(IntegrityVerifierJob(vault, event_publisher=events.append).verify_single,
                                             evidence_id, principal.username)
        except KeyError:
            raise HTTPException(404, "Evidence not found")
        for event in events:
            await ingest(event)
        return detail.model_dump(mode="json")

    @router.get("/api/forensics/evidence/{evidence_id}/download")
    async def download_evidence(evidence_id: str, vault: EvidenceVault = Depends(resolve_vault), principal: Principal = Depends(authorize_request)):
        metadata, data = await verified_bytes(vault, evidence_id, principal.username, "evidence_download")
        await asyncio.to_thread(vault.record_custody, metadata, ChainOfCustodyEntry(
            evidence_id=evidence_id, actor=principal.username, action=CustodyAction.EXPORT,
            expected_hash=metadata.sha256, actual_hash=metadata.sha256, status=CustodyStatus.VERIFIED,
            notes="Verified evidence copy exported through API"))
        return Response(data, media_type="application/octet-stream", headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(metadata.filename, safe='')}",
            "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; sandbox",
        })

    @router.post("/api/forensics/cases/{case_id}/verify")
    async def verify_case(case_id: str, vault: EvidenceVault = Depends(resolve_vault), principal: Principal = Depends(authorize_request)):
        if not await asyncio.to_thread(vault.list_evidence, case_id):
            raise HTTPException(404, "No evidence found for case")
        events = []
        result = await asyncio.to_thread(IntegrityVerifierJob(vault, event_publisher=events.append).run_sweep,
                                         case_id, principal.username)
        for event in events:
            await ingest(event)
        return result.model_dump(mode="json")

    @router.post("/api/forensics/evidence/{evidence_id}/carve/{artifact_index}", status_code=201)
    async def recover_artifact(evidence_id: str, artifact_index: int, vault: EvidenceVault = Depends(resolve_vault), principal: Principal = Depends(authorize_request)):
        metadata, data = await verified_bytes(vault, evidence_id, principal.username, "file_carving")
        artifacts = await asyncio.to_thread(analyzer.carve_files, data)
        if artifact_index < 0 or artifact_index >= len(artifacts):
            raise HTTPException(404, "Carved artifact not found")
        artifact = artifacts[artifact_index]
        child = await asyncio.to_thread(vault.ingest_bytes,
            data[artifact.offset_start:artifact.offset_end], artifact.recovered_name,
            principal.username, metadata.case_id, metadata.source_host,
            notes=f"Derived from evidence:{evidence_id} SHA-256:{metadata.sha256} byte range [{artifact.offset_start},{artifact.offset_end})")
        await ingest(SecurityEvent(source="forensics", event_type="evidence_intake", severity="low",
            entity=Entity(hash=child.sha256), raw={"evidence_id": child.evidence_id, "case_id": child.case_id, "parent_evidence_id": evidence_id}))
        return public_metadata(child)

    @router.post("/api/forensics/recover-deleted", status_code=201)
    async def recover_deleted_pair(body: DeletedPairRequest, vault: EvidenceVault = Depends(resolve_vault), principal: Principal = Depends(authorize_request)):
        if body.metadata_evidence_id == body.content_evidence_id:
            raise HTTPException(422, "Deletion metadata and content must be different evidence items")
        metadata, index_bytes = await verified_bytes(vault, body.metadata_evidence_id, principal.username, "deleted_pair_metadata")
        content, content_bytes = await verified_bytes(vault, body.content_evidence_id, principal.username, "deleted_pair_content")
        if metadata.case_id != content.case_id:
            raise HTTPException(422, "Recovery partners must belong to the same case")
        try:
            recovery = validate_deleted_pair(index_bytes, metadata.filename, content_bytes, content.filename)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        child = await asyncio.to_thread(vault.ingest_bytes, content_bytes, recovery["recovered_filename"],
            principal.username, metadata.case_id, content.source_host,
            notes=f"Deleted-file recovery from metadata evidence:{metadata.evidence_id} SHA-256:{metadata.sha256}; content evidence:{content.evidence_id} SHA-256:{content.sha256}; format:{recovery['format']}")
        await ingest(SecurityEvent(source="forensics", event_type="evidence_intake", severity="low",
            entity=Entity(hash=child.sha256), raw={"evidence_id": child.evidence_id, "case_id": child.case_id,
                "metadata_evidence_id": metadata.evidence_id, "content_evidence_id": content.evidence_id}))
        return {"evidence": public_metadata(child), "recovery": recovery}

    @router.get("/api/reports/forensics/{case_id}")
    async def forensic_report(case_id: str, format: ReportFormat = "json", vault: EvidenceVault = Depends(resolve_vault), principal: Principal = Depends(authorize_request)):
        items = await asyncio.to_thread(vault.list_evidence, case_id)
        if not items:
            raise HTTPException(404, "No evidence found for case")
        snapshots, analyses = [], {}
        for item in items:
            metadata, analysis = await verified_analysis(vault, item.evidence_id, principal.username, "forensic_report")
            snapshots.append(public_metadata(metadata))
            analyses[item.evidence_id] = analysis
        return report_response(build_forensic_report(case_id, snapshots, analyses), format)

    return router
