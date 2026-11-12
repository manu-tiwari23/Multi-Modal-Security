"""
Phishing Explanation Generator.

Phase 5, Feature 4 — Synthesizes structured, auditable, human-readable
explanations answering *why* an email, URL, or attachment scored the way it
did. Supports single-verdict explanations and cross-vector composite
explanations (email + URLs + attachments).

Complies with:
- ARCHITECTURE.md §4.4 & §2 — Explainability: every AI/heuristic verdict must
  show *why*, never just a bare number.
- .agents/skills/phishing-detection/SKILL.md — stateless service, mandatory
  specific signal citations, ASCII-safe evidence rendering.
- AGENTS.md — human-in-the-loop recommended actions (never autonomous
  containment execution).
"""

from __future__ import annotations

from typing import Optional

from src.phishing.attachment_analyzer import safe_ascii
from src.phishing.models import (
    CategoryContribution,
    MitreMappingDetail,
    PhishingSeverity,
    PhishingSignal,
    PhishingVerdict,
    SignalAttribution,
    SignalCategory,
    StructuredExplanation,
)


# ---------------------------------------------------------------------------
# Human-Readable Catalogs (Categories, Severity Order, MITRE ATT&CK, Actions)
# ---------------------------------------------------------------------------

CATEGORY_LABELS: dict[SignalCategory, str] = {
    SignalCategory.HEADER_ANOMALY: "Email Header Anomaly",
    SignalCategory.SENDER_REPUTATION: "Sender Reputation Risk",
    SignalCategory.AUTHENTICATION_FAILURE: "Email Authentication Failure (SPF/DKIM/DMARC)",
    SignalCategory.URGENCY_LANGUAGE: "Urgency & Coercion Language",
    SignalCategory.SUSPICIOUS_LINK: "Suspicious Link Structure",
    SignalCategory.CREDENTIAL_HARVESTING: "Credential Harvesting Indicators",
    SignalCategory.IMPERSONATION: "Brand / Executive Impersonation",
    SignalCategory.ATTACHMENT_RISK: "Malicious Attachment Indicators",
    SignalCategory.CONTENT_ANOMALY: "HTML / Content Evasion Anomaly",
    SignalCategory.DOMAIN_AGE: "Newly Registered / Young Domain",
    SignalCategory.URL_OBFUSCATION: "URL Obfuscation & Masking",
    SignalCategory.SOCIAL_ENGINEERING: "Social Engineering Pretext",
    SignalCategory.HOMOGRAPH_ATTACK: "IDN Homograph / Typosquatting Attack",
    SignalCategory.THREAT_INTEL_MATCH: "Threat Intelligence Blocklist Match",
    SignalCategory.IP_HOST: "Raw / Obfuscated IP Host",
}

SEVERITY_RANK: dict[PhishingSeverity, int] = {
    PhishingSeverity.SAFE: 0,
    PhishingSeverity.LOW: 1,
    PhishingSeverity.MEDIUM: 2,
    PhishingSeverity.HIGH: 3,
    PhishingSeverity.CRITICAL: 4,
}

MITRE_CATALOG: dict[str, tuple[str, str]] = {
    "T1566": ("Phishing", "Initial Access"),
    "T1566.001": ("Spearphishing Attachment", "Initial Access"),
    "T1566.002": ("Spearphishing Link", "Initial Access"),
    "T1204.001": ("User Execution: Malicious Link", "Execution"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1036.007": ("Masquerading: Double File Extension / RTLO", "Defense Evasion"),
    "T1036.008": ("Masquerading: Masquerade File Type", "Defense Evasion"),
    "T1221": ("Template Injection", "Defense Evasion"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1027.002": ("Obfuscated Files: Software Packing", "Defense Evasion"),
    "T1027.006": ("Obfuscated Files: HTML Smuggling", "Defense Evasion"),
    "T1583.001": ("Acquire Infrastructure: Domains", "Resource Development"),
    "T1584.001": ("Compromise Infrastructure: Domains", "Resource Development"),
    "T1499": ("Endpoint Denial of Service", "Impact"),
}

CATEGORY_RECOMMENDATIONS: dict[SignalCategory, str] = {
    SignalCategory.AUTHENTICATION_FAILURE: (
        "Verify sender SPF/DKIM/DMARC alignment and quarantine spoofed external messages."
    ),
    SignalCategory.HEADER_ANOMALY: (
        "Inspect full SMTP Received hops and Reply-To mismatch before releasing message."
    ),
    SignalCategory.IMPERSONATION: (
        "Alert targeted brand/executive impersonation recipients via out-of-band verification."
    ),
    SignalCategory.HOMOGRAPH_ATTACK: (
        "Block lookalike/punycode domain at DNS resolver and web proxy (requires analyst approval)."
    ),
    SignalCategory.THREAT_INTEL_MATCH: (
        "Block matched IOC across mail gateway, firewall, and EDR (requires analyst approval)."
    ),
    SignalCategory.CREDENTIAL_HARVESTING: (
        "Check proxy/auth logs for clicks or credential submissions; force password/MFA reset if exposed."
    ),
    SignalCategory.ATTACHMENT_RISK: (
        "Quarantine attachment by SHA-256 hash; never open outside an isolated malware sandbox."
    ),
    SignalCategory.URL_OBFUSCATION: (
        "Block obfuscated destination URL and inspect any users who followed the redirect."
    ),
    SignalCategory.IP_HOST: (
        "Block direct-IP HTTP/HTTPS destination at perimeter firewall (requires analyst approval)."
    ),
    SignalCategory.CONTENT_ANOMALY: (
        "Strip active HTML/script smuggling payloads and warn targeted recipients."
    ),
    SignalCategory.URGENCY_LANGUAGE: (
        "Flag coercive social-engineering pretext in user awareness telemetry."
    ),
}


# ---------------------------------------------------------------------------
# ExplanationGenerator — Stateless Explainability Synthesizer
# ---------------------------------------------------------------------------

class ExplanationGenerator:
    """Stateless generator that transforms PhishingVerdict objects into
    structured, transparent explanations of *why* a score was assigned.
    """

    def explain(
        self,
        verdict: PhishingVerdict,
        target: Optional[str] = None,
    ) -> StructuredExplanation:
        """Build a StructuredExplanation for a single PhishingVerdict."""
        target_summary = self._resolve_target_summary(verdict, target)
        signals = list(verdict.signals)

        if not signals:
            return self._build_clean_explanation(verdict, target_summary)

        raw_score = round(sum(max(0.0, s.score_contribution) for s in signals), 1)
        score_capped = raw_score > verdict.score
        denom = raw_score if raw_score > 0 else float(len(signals))

        top_factors = self._build_signal_attributions(signals, denom, raw_score)
        category_breakdown = self._build_category_breakdown(signals, denom, raw_score)
        mitre_details = self._build_mitre_details(verdict, signals)
        recommended_actions = self._build_recommendations(verdict, signals)

        headline = self._build_headline(
            verdict=verdict,
            target_summary=target_summary,
            category_breakdown=category_breakdown,
            top_factors=top_factors,
            score_capped=score_capped,
            raw_score=raw_score,
        )
        narrative = self._build_narrative(
            verdict=verdict,
            target_summary=target_summary,
            category_breakdown=category_breakdown,
            top_factors=top_factors,
            score_capped=score_capped,
            raw_score=raw_score,
        )

        explanation = StructuredExplanation(
            verdict_id=verdict.verdict_id,
            analysis_type=verdict.analysis_type,
            target_summary=target_summary,
            score=verdict.score,
            raw_score=raw_score,
            score_capped=score_capped,
            severity=verdict.severity,
            is_phishing=verdict.is_phishing,
            confidence=verdict.confidence,
            headline=headline,
            narrative=narrative,
            category_breakdown=category_breakdown,
            top_factors=top_factors,
            mitre_details=mitre_details,
            recommended_actions=recommended_actions,
        )
        explanation.formatted_text = self._render_text(explanation)
        explanation.formatted_markdown = self._render_markdown(explanation)
        return explanation

    def explain_composite(
        self,
        email_verdict: Optional[PhishingVerdict] = None,
        url_verdicts: Optional[list[PhishingVerdict]] = None,
        attachment_verdicts: Optional[list[PhishingVerdict]] = None,
        target: Optional[str] = None,
    ) -> StructuredExplanation:
        """Synthesize a unified multi-vector explanation across email, URLs, and attachments."""
        url_verdicts = url_verdicts or []
        attachment_verdicts = attachment_verdicts or []
        all_verdicts: list[PhishingVerdict] = []
        if email_verdict:
            all_verdicts.append(email_verdict)
        all_verdicts.extend(url_verdicts)
        all_verdicts.extend(attachment_verdicts)

        if not all_verdicts:
            empty_verdict = PhishingVerdict(
                analysis_type="composite",
                score=0.0,
                severity=PhishingSeverity.SAFE,
                is_phishing=False,
                confidence=0.5,
                signals=[],
                explanation="No verdicts provided for composite explanation.",
            )
            return self.explain(empty_verdict, target=target or "composite-scan")

        # Merge signals across modalities, deduplicating identical (name, evidence) pairs
        merged_signals: list[PhishingSignal] = []
        seen_keys: set[tuple[str, str]] = set()
        for v in all_verdicts:
            for sig in v.signals:
                key = (sig.name, safe_ascii(sig.evidence))
                if key not in seen_keys:
                    seen_keys.add(key)
                    merged_signals.append(sig)

        # Cross-vector corroboration bonus if >=2 distinct analysis types flagged phishing
        flagged_modalities = {v.analysis_type for v in all_verdicts if v.is_phishing}
        max_vector_score = max(v.score for v in all_verdicts)
        raw_merged = sum(s.score_contribution for s in merged_signals)
        corroboration_bonus = 10.0 if len(flagged_modalities) >= 2 else 0.0
        composite_score = min(100.0, round(max(max_vector_score + corroboration_bonus, raw_merged), 1))

        severity = self._score_to_severity(composite_score)
        is_phishing = any(v.is_phishing for v in all_verdicts) or composite_score >= 40.0
        confidence = round(max(v.confidence for v in all_verdicts), 2)

        mitre_set: set[str] = set()
        for v in all_verdicts:
            mitre_set.update(v.mitre_techniques)
        for s in merged_signals:
            if s.mitre_technique:
                mitre_set.add(s.mitre_technique)

        target_desc = target or self._composite_target_summary(email_verdict, url_verdicts, attachment_verdicts)
        composite_verdict = PhishingVerdict(
            email_id=email_verdict.email_id if email_verdict else None,
            target_url=url_verdicts[0].target_url if url_verdicts else None,
            target_filename=attachment_verdicts[0].target_filename if attachment_verdicts else None,
            analysis_type="composite",
            score=composite_score,
            severity=severity,
            is_phishing=is_phishing,
            confidence=confidence,
            signals=merged_signals,
            mitre_techniques=sorted(mitre_set),
        )
        return self.explain(composite_verdict, target=target_desc)

    # ------------------------------------------------------------------
    # Internal Builders
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_target_summary(verdict: PhishingVerdict, target: Optional[str]) -> str:
        if target:
            return safe_ascii(target)
        if verdict.target_filename:
            return f"Attachment '{safe_ascii(verdict.target_filename)}'"
        if verdict.target_url:
            return f"URL '{safe_ascii(verdict.target_url)}'"
        if verdict.email_id:
            return f"Email ({safe_ascii(verdict.email_id)})"
        return f"{verdict.analysis_type.title()} target"

    @staticmethod
    def _composite_target_summary(
        email_verdict: Optional[PhishingVerdict],
        url_verdicts: list[PhishingVerdict],
        attachment_verdicts: list[PhishingVerdict],
    ) -> str:
        parts: list[str] = []
        if email_verdict:
            parts.append(f"Email ({safe_ascii(email_verdict.email_id or 'msg')})")
        if url_verdicts:
            parts.append(f"{len(url_verdicts)} URL(s)")
        if attachment_verdicts:
            parts.append(f"{len(attachment_verdicts)} Attachment(s)")
        return " + ".join(parts) if parts else "Composite target"

    def _build_clean_explanation(
        self,
        verdict: PhishingVerdict,
        target_summary: str,
    ) -> StructuredExplanation:
        headline = (
            f"{target_summary} scored {verdict.score:.1f}/100 ({verdict.severity.value.upper()}) - "
            f"no phishing or malicious indicators fired."
        )
        narrative = (
            f"All static heuristics and cached threat intelligence checks passed for {target_summary}. "
            f"Because 0 risk signals triggered, the verdict is classified as SAFE with "
            f"{int(verdict.confidence * 100)}% confidence."
        )
        actions = [
            "No containment action required; continue standard monitoring.",
        ]
        explanation = StructuredExplanation(
            verdict_id=verdict.verdict_id,
            analysis_type=verdict.analysis_type,
            target_summary=target_summary,
            score=verdict.score,
            raw_score=0.0,
            score_capped=False,
            severity=verdict.severity,
            is_phishing=verdict.is_phishing,
            confidence=verdict.confidence,
            headline=headline,
            narrative=narrative,
            category_breakdown=[],
            top_factors=[],
            mitre_details=[],
            recommended_actions=actions,
        )
        explanation.formatted_text = self._render_text(explanation)
        explanation.formatted_markdown = self._render_markdown(explanation)
        return explanation

    def _build_signal_attributions(
        self,
        signals: list[PhishingSignal],
        denom: float,
        raw_score: float,
    ) -> list[SignalAttribution]:
        sorted_sigs = sorted(
            signals,
            key=lambda s: (s.score_contribution, SEVERITY_RANK.get(s.severity, 0)),
            reverse=True,
        )
        attributions: list[SignalAttribution] = []
        for s in sorted_sigs:
            weight = s.score_contribution if raw_score > 0 else 1.0
            share = round((weight / denom) * 100.0, 1)
            attributions.append(SignalAttribution(
                signal_name=safe_ascii(s.name),
                category=s.category.value,
                severity=s.severity,
                score_contribution=round(s.score_contribution, 1),
                share_percent=share,
                reason=safe_ascii(s.description),
                evidence=safe_ascii(s.evidence),
                mitre_technique=s.mitre_technique,
            ))
        return attributions

    def _build_category_breakdown(
        self,
        signals: list[PhishingSignal],
        denom: float,
        raw_score: float,
    ) -> list[CategoryContribution]:
        grouped: dict[SignalCategory, list[PhishingSignal]] = {}
        for s in signals:
            grouped.setdefault(s.category, []).append(s)

        breakdown: list[CategoryContribution] = []
        for cat, cat_sigs in grouped.items():
            cat_points = round(sum(max(0.0, s.score_contribution) for s in cat_sigs), 1)
            weight = cat_points if raw_score > 0 else float(len(cat_sigs))
            share = round((weight / denom) * 100.0, 1)
            highest = max(cat_sigs, key=lambda s: SEVERITY_RANK.get(s.severity, 0)).severity
            top_names = [
                safe_ascii(s.name)
                for s in sorted(cat_sigs, key=lambda x: x.score_contribution, reverse=True)[:3]
            ]
            breakdown.append(CategoryContribution(
                category=cat,
                category_label=CATEGORY_LABELS.get(cat, cat.value.replace("_", " ").title()),
                signal_count=len(cat_sigs),
                raw_points=cat_points,
                share_percent=share,
                highest_severity=highest,
                top_signals=top_names,
            ))

        breakdown.sort(key=lambda c: (c.raw_points, c.signal_count), reverse=True)
        return breakdown

    @staticmethod
    def _build_mitre_details(
        verdict: PhishingVerdict,
        signals: list[PhishingSignal],
    ) -> list[MitreMappingDetail]:
        ids: set[str] = set(verdict.mitre_techniques)
        for s in signals:
            if s.mitre_technique:
                ids.add(s.mitre_technique)

        details: list[MitreMappingDetail] = []
        for tid in sorted(ids):
            name, tactic = MITRE_CATALOG.get(tid, ("Phishing / Social Engineering Technique", "Initial Access"))
            details.append(MitreMappingDetail(
                technique_id=tid,
                technique_name=name,
                tactic=tactic,
            ))
        return details

    @staticmethod
    def _build_recommendations(
        verdict: PhishingVerdict,
        signals: list[PhishingSignal],
    ) -> list[str]:
        if not verdict.is_phishing and verdict.severity in (PhishingSeverity.SAFE, PhishingSeverity.LOW):
            return [
                "Low-risk verdict: exercise normal caution and verify unexpected requests out-of-band.",
            ]

        actions: list[str] = []
        seen_cats: set[SignalCategory] = set()
        # Order recommendations by highest-contributing categories first
        for sig in sorted(signals, key=lambda s: s.score_contribution, reverse=True):
            if sig.category not in seen_cats:
                seen_cats.add(sig.category)
                rec = CATEGORY_RECOMMENDATIONS.get(sig.category)
                if rec and rec not in actions:
                    actions.append(rec)

        if verdict.severity in (PhishingSeverity.HIGH, PhishingSeverity.CRITICAL):
            actions.append(
                "Escalate to SOC Incident Response for analyst-approved containment (never execute automated blocks without review)."
            )
        return actions[:6]

    @staticmethod
    def _build_headline(
        verdict: PhishingVerdict,
        target_summary: str,
        category_breakdown: list[CategoryContribution],
        top_factors: list[SignalAttribution],
        score_capped: bool,
        raw_score: float,
    ) -> str:
        status = "PHISHING" if verdict.is_phishing else "SUSPICIOUS"
        if verdict.severity == PhishingSeverity.SAFE:
            status = "SAFE"

        drivers = [
            f"{f.signal_name} (+{f.score_contribution:.1f})"
            for f in top_factors[:3]
        ]
        driver_str = ", ".join(drivers)
        cap_note = f" [capped from {raw_score:.1f}]" if score_capped else ""
        return (
            f"{target_summary} classified as {status} ({verdict.severity.value.upper()}, "
            f"score {verdict.score:.1f}/100{cap_note}) driven by {len(top_factors)} signal(s): {driver_str}."
        )

    @staticmethod
    def _build_narrative(
        verdict: PhishingVerdict,
        target_summary: str,
        category_breakdown: list[CategoryContribution],
        top_factors: list[SignalAttribution],
        score_capped: bool,
        raw_score: float,
    ) -> str:
        top_cats = ", ".join(
            f"{c.category_label} ({c.share_percent:.0f}%)"
            for c in category_breakdown[:3]
        )
        lead = top_factors[0]
        parts = [
            f"Analysis of {target_summary} produced a risk score of {verdict.score:.1f}/100 "
            f"({verdict.severity.value.upper()}, {int(verdict.confidence * 100)}% confidence) "
            f"across {len(category_breakdown)} signal category(ies).",
        ]
        if score_capped:
            parts.append(
                f"Combined indicator weights totaled {raw_score:.1f} raw points and were capped at the 100.0 maximum."
            )
        parts.append(
            f"Primary risk drivers: {top_cats}. "
            f"The single strongest indicator was '{lead.signal_name}' (+{lead.score_contribution:.1f} pts): {lead.reason}."
        )
        return " ".join(parts)

    @staticmethod
    def _score_to_severity(score: float) -> PhishingSeverity:
        if score >= 80.0:
            return PhishingSeverity.CRITICAL
        if score >= 60.0:
            return PhishingSeverity.HIGH
        if score >= 35.0:
            return PhishingSeverity.MEDIUM
        if score >= 15.0:
            return PhishingSeverity.LOW
        return PhishingSeverity.SAFE

    @staticmethod
    def _render_text(exp: StructuredExplanation) -> str:
        lines = [
            exp.headline,
            "",
            f"Summary: {exp.narrative}",
        ]
        if exp.category_breakdown:
            lines.append("")
            lines.append("Score Breakdown by Category:")
            for cat in exp.category_breakdown:
                lines.append(
                    f"  - {cat.category_label}: +{cat.raw_points:.1f} pts ({cat.share_percent:.1f}% share, "
                    f"{cat.signal_count} signal(s), max {cat.highest_severity.value.upper()})"
                )
        if exp.top_factors:
            lines.append("")
            lines.append("Contributing Signals:")
            for idx, fac in enumerate(exp.top_factors, 1):
                lines.append(
                    f"  [{idx}] {fac.signal_name} (+{fac.score_contribution:.1f} pts / {fac.share_percent:.1f}%, "
                    f"{fac.severity.value.upper()}): {fac.reason}"
                )
                if fac.evidence:
                    lines.append(f"      Evidence: {fac.evidence}")
        if exp.mitre_details:
            lines.append("")
            lines.append(
                "MITRE ATT&CK: "
                + ", ".join(f"{m.technique_id} ({m.technique_name})" for m in exp.mitre_details)
            )
        if exp.recommended_actions:
            lines.append("")
            lines.append("Recommended Actions:")
            for act in exp.recommended_actions:
                lines.append(f"  * {act}")
        return "\n".join(lines)

    @staticmethod
    def _render_markdown(exp: StructuredExplanation) -> str:
        lines = [
            f"### Phishing Risk Explanation - {exp.severity.value.upper()} ({exp.score:.1f}/100)",
            f"**Target:** `{exp.target_summary}` | **Confidence:** {int(exp.confidence * 100)}% | "
            f"**Verdict:** {'Phishing' if exp.is_phishing else 'Clean / Low Risk'}",
            "",
            exp.narrative,
        ]
        if exp.category_breakdown:
            lines.append("")
            lines.append("#### Category Breakdown")
            lines.append("| Category | Points | Share | Signals | Max Severity |")
            lines.append("|---|---:|---:|---:|---|")
            for cat in exp.category_breakdown:
                lines.append(
                    f"| {cat.category_label} | +{cat.raw_points:.1f} | {cat.share_percent:.1f}% | "
                    f"{cat.signal_count} | {cat.highest_severity.value.upper()} |"
                )
        if exp.top_factors:
            lines.append("")
            lines.append("#### Specific Signals Fired")
            for fac in exp.top_factors:
                ev = f" - `Evidence: {fac.evidence}`" if fac.evidence else ""
                lines.append(
                    f"- **{fac.signal_name}** (`+{fac.score_contribution:.1f}` pts, {fac.severity.value.upper()}): "
                    f"{fac.reason}{ev}"
                )
        if exp.mitre_details:
            lines.append("")
            lines.append("#### MITRE ATT&CK Mapping")
            for m in exp.mitre_details:
                lines.append(f"- `{m.technique_id}` - **{m.technique_name}** (*{m.tactic}*)")
        if exp.recommended_actions:
            lines.append("")
            lines.append("#### Recommended Actions (Analyst Approval Required)")
            for act in exp.recommended_actions:
                lines.append(f"- {act}")
        return "\n".join(lines)
