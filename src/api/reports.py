"""HTTP representation of reports, shared by report endpoints."""

from typing import Literal

from fastapi.responses import Response

from src.reporting import Report

ReportFormat = Literal["json", "html", "markdown"]


def report_response(report: Report, format: ReportFormat):
    if format == "json":
        return report.model_dump(mode="json")
    extension, media_type, content = (
        ("html", "text/html", report.to_html()) if format == "html"
        else ("md", "text/markdown", report.to_markdown())
    )
    return Response(content=content, media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="mms-{report.kind}-{report.report_id}.{extension}"',
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    })
