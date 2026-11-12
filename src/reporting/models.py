"""Report documents with safe standalone HTML and Markdown renderers."""

from datetime import datetime, timezone
from html import escape
from uuid import uuid4

from pydantic import BaseModel, Field


def markdown_text(value: str) -> str:
    # Source evidence is untrusted text, never Markdown/HTML instructions.
    value = escape(str(value), quote=False).replace("\r", " ").replace("\n", " ")
    for char in "\\`*_{}[]()#+-.!|":
        value = value.replace(char, "\\" + char)
    return value


class ReportSection(BaseModel):
    title: str
    paragraphs: list[str] = Field(default_factory=list)
    columns: list[str] = Field(default_factory=list)
    rows: list[list[str]] = Field(default_factory=list)


class Report(BaseModel):
    report_id: str = Field(default_factory=lambda: uuid4().hex)
    kind: str
    subject_id: str
    title: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    summary: str
    sections: list[ReportSection] = Field(default_factory=list)
    source_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    def to_markdown(self) -> str:
        text = markdown_text
        lines = [f"# {text(self.title)}", "", f"Report: {self.report_id}",
                 f"Subject: {text(self.subject_id)}", f"Generated: {self.generated_at.isoformat()}",
                 "", text(self.summary)]
        for section in self.sections:
            lines.extend(["", f"## {text(section.title)}", ""])
            lines.extend(text(p) + "\n" for p in section.paragraphs)
            if section.columns:
                lines.append("| " + " | ".join(map(text, section.columns)) + " |")
                lines.append("| " + " | ".join("---" for _ in section.columns) + " |")
                lines.extend("| " + " | ".join(map(text, row)) + " |" for row in section.rows)
        lines.extend(["", "## Sources", "", *[f"- {text(s)}" for s in self.source_ids],
                      "", "## Limitations", "", *[f"- {text(s)}" for s in self.limitations]])
        return "\n".join(lines) + "\n"

    def to_html(self) -> str:
        text = lambda value: escape(str(value), quote=True)
        body = [f"<header><p>MULTI MODAL SECURITY / {text(self.kind.upper())}</p>",
                f"<h1>{text(self.title)}</h1>",
                f"<p>Subject: {text(self.subject_id)}<br>Report: {self.report_id}<br>",
                f"Generated: {self.generated_at.isoformat()}</p></header>",
                f"<p class='summary'>{text(self.summary)}</p>"]
        for section in self.sections:
            body.append(f"<section><h2>{text(section.title)}</h2>")
            body.extend(f"<p>{text(p)}</p>" for p in section.paragraphs)
            if section.columns:
                body.append("<table><thead><tr>" + "".join(f"<th scope='col'>{text(c)}</th>" for c in section.columns) + "</tr></thead><tbody>")
                body.extend("<tr>" + "".join(f"<td>{text(c)}</td>" for c in row) + "</tr>" for row in section.rows)
                body.append("</tbody></table>")
            body.append("</section>")
        for title, items in (("Sources", self.source_ids), ("Limitations", self.limitations)):
            body.append(f"<section><h2>{title}</h2><ul>" + "".join(f"<li>{text(i)}</li>" for i in items) + "</ul></section>")
        return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
                "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
                f"<title>{text(self.title)}</title><style>"
                "body{font:15px/1.6 system-ui,sans-serif;color:#142437;max-width:1100px;margin:48px auto;padding:0 28px}"
                "header{border-bottom:3px solid #087f8c;padding-bottom:20px}header p{color:#4b6173;font-size:12px}"
                "h1{font-size:30px;line-height:1.2}h2{font-size:20px;margin-top:32px}.summary{font-size:18px}"
                "table{border-collapse:collapse;width:100%;font-size:12px;table-layout:fixed}"
                "th,td{padding:10px;border:1px solid #d5dfe7;text-align:left;vertical-align:top;overflow-wrap:anywhere}"
                "th{background:#edf4f7}li,p{overflow-wrap:anywhere}"
                "@media print{body{margin:0;padding:0;font-size:11px}h2{break-after:avoid}tr{break-inside:avoid}thead{display:table-header-group}}"
                "</style></head><body>" + "".join(body) + "</body></html>")
