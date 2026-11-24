# backend/app/reporting/pdf_report.py
#
# Renders a saved scan (row from the scans table, with its report) as a
# PDF with reportlab:
#
#   cover            API name, target URL, scan date, scan options
#   1 Executive summary   overall risk, severity counts, tests, deployment score
#   2 Security findings   table sorted by severity (+ proof-of-concept details)
#   3 API tests           one table per endpoint
#   4 Deployment checks
#   5 Recommendations
#   6 AI analysis         the LLM's markdown, rendered
#
# The built-in PDF fonts (Helvetica/Courier) only cover Windows-1252, so all
# text goes through clean() first: LLM output is full of non-breaking
# hyphens, narrow spaces, arrows and emoji that would otherwise print as
# black boxes.

from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional
from urllib.parse import urlparse
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (
    BaseDocTemplate, CondPageBreak, Flowable, Frame, KeepTogether, NextPageTemplate,
    PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle,
)
from reportlab.platypus.doctemplate import Indenter
from reportlab.platypus.flowables import HRFlowable

APP_NAME = "API Sentinel"

PAGE_W, PAGE_H = A4
MARGIN_X       = 18 * mm
CONTENT_W      = PAGE_W - 2 * MARGIN_X

# ─────────────────────────────────────────
# Palette
# ─────────────────────────────────────────

INK       = colors.HexColor("#101828")
TEXT      = colors.HexColor("#344054")
MUTED     = colors.HexColor("#667085")
LINE      = colors.HexColor("#e4e7ec")
SURFACE   = colors.HexColor("#f9fafb")
NAVY      = colors.HexColor("#0b1b33")
NAVY_SOFT = colors.HexColor("#9fb0c9")
ACCENT    = colors.HexColor("#4f46e5")
PASS      = colors.HexColor("#067647")
PASS_BG   = colors.HexColor("#ecfdf3")
FAIL      = colors.HexColor("#b42318")
FAIL_BG   = colors.HexColor("#fef3f2")
SKIP      = colors.HexColor("#667085")
SKIP_BG   = colors.HexColor("#f2f4f7")

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_COLOR = {
    "CRITICAL": colors.HexColor("#7a0916"),
    "HIGH":     colors.HexColor("#d92d20"),
    "MEDIUM":   colors.HexColor("#dc6803"),
    "LOW":      colors.HexColor("#1570ef"),
    "INFO":     colors.HexColor("#667085"),
    "NONE":     colors.HexColor("#067647"),
}
SEV_RANK  = {s: i for i, s in enumerate(SEVERITIES)}
CONF_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

AUTH_LABELS = {"bearer": "Bearer token", "api_key": "API key header", "basic": "HTTP Basic"}


def _hex(c) -> str:
    return "#" + c.hexval()[2:]


# ─────────────────────────────────────────
# Text helpers
# ─────────────────────────────────────────

_CHAR_MAP = {
    "‐": "-", "‑": "-", "‒": "-", "−": "-", "⁃": "-",
    " ": " ", " ": " ", " ": " ", " ": " ", " ": " ", " ": " ",
    "​": "", "‌": "", "‍": "", "️": "", "﻿": "",
    "→": "->", "←": "<-", "↔": "<->", "⇒": "=>",
    "≤": "<=", "≥": ">=", "≠": "!=", "≈": "~", "×": "x",
    "✓": "", "✔": "", "✅": "", "❌": "", "✗": "", "✘": "",
    "⚠": "", "❗": "!", "•": "•",
}


def clean(text) -> str:
    """Make text printable in the built-in (Windows-1252) PDF fonts."""
    if text is None:
        return ""
    out = []
    for ch in str(text):
        if ch in _CHAR_MAP:
            out.append(_CHAR_MAP[ch])
        elif ch in "\n\t" or ord(ch) >= 32:
            try:
                ch.encode("cp1252")
                out.append(ch)
            except UnicodeEncodeError:
                out.append(unicodedata.normalize("NFKD", ch).encode("ascii", "ignore").decode())
    return "".join(out)


def esc(text) -> str:
    """Plain text -> safe Paragraph markup."""
    return escape(clean(text))


def md_inline(text: str) -> str:
    """Inline markdown (bold, italic, code, <br>) -> Paragraph markup."""
    text = re.sub(r"<br\s*/?>", "\x00", clean(text), flags=re.I)
    text = escape(text)
    codes: list[str] = []

    def stash(m):
        codes.append(m.group(1))
        return f"\x01{len(codes) - 1}\x01"

    text = re.sub(r"`([^`]+)`", stash, text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<![\w])__(.+?)__(?![\w])", r"<b>\1</b>", text)
    text = re.sub(r"(?<![\w*])\*(?![\s*])(.+?)(?<![\s*])\*(?![\w*])", r"<i>\1</i>", text)
    text = re.sub(r"\x01(\d+)\x01",
                  lambda m: f'<font face="Courier" color="#9e1c3c">{codes[int(m.group(1))]}</font>', text)
    return text.replace("\x00", "<br/>")


def _strip_tags(markup: str) -> str:
    return re.sub(r"<[^>]+>", "", markup)


def para(markup: str, style: ParagraphStyle, **kw) -> Paragraph:
    """Paragraph that falls back to plain text if the markup is malformed."""
    try:
        return Paragraph(markup, style, **kw)
    except ValueError:
        # markup is already entity-escaped; dropping the tags leaves valid text
        return Paragraph(_strip_tags(markup), style, **kw)


def fmt_date(value: Optional[str]) -> str:
    """ISO timestamp (naive = UTC, as stored) -> '24 Nov 2026, 10:00 UTC'."""
    if not value:
        return "-"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return str(value)
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%d %b %Y, %H:%M UTC")


def humanize(name: str) -> str:
    name = (name or "").replace("_", " ").strip()
    return name[:1].upper() + name[1:]


def short_url(url: str, base: str) -> str:
    """http://host:8001/users/1?x=1 -> /users/1?x=1 when it is on the target."""
    if base and url.startswith(base):
        return url[len(base):] or "/"
    p = urlparse(url)
    return (p.path or "/") + (f"?{p.query}" if p.query else "") if p.netloc else url


def slug(text: str) -> str:
    ascii_text = unicodedata.normalize("NFKD", str(text)).encode("ascii", "ignore").decode()
    s = re.sub(r"[^A-Za-z0-9]+", "-", ascii_text).strip("-").lower()
    return s[:50] or "api"


# ─────────────────────────────────────────
# Styles
# ─────────────────────────────────────────

def _styles() -> dict:
    base = dict(fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=TEXT)
    s = {
        "body":     ParagraphStyle("body", **base, spaceAfter=6),
        "small":    ParagraphStyle("small", **{**base, "fontSize": 8.2, "leading": 11}),
        "muted":    ParagraphStyle("muted", **{**base, "fontSize": 8.2, "leading": 11, "textColor": MUTED}),
        "cell":     ParagraphStyle("cell", **{**base, "fontSize": 8.4, "leading": 11}),
        "cellb":    ParagraphStyle("cellb", **{**base, "fontName": "Helvetica-Bold", "fontSize": 8.4,
                                               "leading": 11, "textColor": INK}),
        "th":       ParagraphStyle("th", **{**base, "fontName": "Helvetica-Bold", "fontSize": 7.6,
                                            "leading": 10, "textColor": MUTED}),
        "code":     ParagraphStyle("code", fontName="Courier", fontSize=7.6, leading=10,
                                   textColor=INK, splitLongWords=True),
        "h1":       ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=17, leading=21,
                                   textColor=INK, spaceBefore=4, spaceAfter=4),
        "h2":       ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11.5, leading=15,
                                   textColor=INK, spaceBefore=12, spaceAfter=6),
        "h3":       ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=10, leading=13,
                                   textColor=INK, spaceBefore=8, spaceAfter=4),
        "bullet":   ParagraphStyle("bullet", **base, leftIndent=14, bulletIndent=3, spaceAfter=3),
        "kpi_num":  ParagraphStyle("kpi_num", fontName="Helvetica-Bold", fontSize=19, leading=22,
                                   textColor=INK),
        "kpi_lbl":  ParagraphStyle("kpi_lbl", fontName="Helvetica", fontSize=7.6, leading=10,
                                   textColor=MUTED),
        "kpi_sub":  ParagraphStyle("kpi_sub", fontName="Helvetica", fontSize=7.6, leading=10,
                                   textColor=MUTED),
        # cover
        "c_brand":  ParagraphStyle("c_brand", fontName="Helvetica-Bold", fontSize=9, leading=12,
                                   textColor=NAVY_SOFT),
        "c_kicker": ParagraphStyle("c_kicker", fontName="Helvetica", fontSize=12, leading=16,
                                   textColor=NAVY_SOFT),
        "c_title":  ParagraphStyle("c_title", fontName="Helvetica-Bold", fontSize=28, leading=33,
                                   textColor=colors.white),
        "c_sub":    ParagraphStyle("c_sub", fontName="Helvetica", fontSize=10.5, leading=14,
                                   textColor=colors.HexColor("#d0d8e6")),
        "kv_key":   ParagraphStyle("kv_key", **{**base, "fontSize": 8.6, "textColor": MUTED}),
        "kv_val":   ParagraphStyle("kv_val", **{**base, "fontSize": 9.2, "textColor": INK}),
        "badge":    ParagraphStyle("badge", fontName="Helvetica-Bold", fontSize=7.4, leading=9,
                                   textColor=colors.white, alignment=TA_CENTER),
        "right":    ParagraphStyle("right", **{**base, "fontSize": 8.4, "leading": 11, "alignment": TA_RIGHT}),
    }
    return s


ST = _styles()


# ─────────────────────────────────────────
# Small building blocks
# ─────────────────────────────────────────

class Bar(Flowable):
    """Horizontal proportion bar for the severity breakdown."""

    def __init__(self, value: int, maximum: int, color, width: float, height: float = 7):
        super().__init__()
        self.value, self.maximum, self.color = value, max(maximum, 1), color
        self.width, self.height = width, height

    def wrap(self, *_):
        return self.width, self.height

    def draw(self):
        c = self.canv
        c.setFillColor(SKIP_BG)
        c.roundRect(0, 0, self.width, self.height, 2, stroke=0, fill=1)
        if self.value:
            c.setFillColor(self.color)
            c.roundRect(0, 0, max(self.width * self.value / self.maximum, 4), self.height, 2, stroke=0, fill=1)


def badge(text: str, color) -> Table:
    """Coloured pill used for severity and pass/fail."""
    t = Table([[Paragraph(esc(text), ST["badge"])]], colWidths=[17 * mm], rowHeights=[4.6 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("ROUNDEDCORNERS", [2, 2, 2, 2]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1),
    ]))
    return t


def section(title: str, number: Optional[int] = None) -> list:
    label = f"{number}&nbsp;&nbsp;{esc(title)}" if number else esc(title)
    return [
        Paragraph(label, ST["h1"]),
        HRFlowable(width="100%", thickness=1.2, color=ACCENT, spaceBefore=2, spaceAfter=10, hAlign="LEFT"),
    ]


def grid_style(header_rows: int = 1, zebra: bool = True) -> list:
    cmds = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, header_rows - 1), (-1, header_rows - 1), 0.8, colors.HexColor("#d0d5dd")),
        ("LINEBELOW", (0, header_rows), (-1, -1), 0.4, LINE),
        ("BACKGROUND", (0, 0), (-1, header_rows - 1), SURFACE),
    ]
    if zebra:
        cmds.append(("ROWBACKGROUNDS", (0, header_rows), (-1, -1), [colors.white, colors.HexColor("#fcfcfd")]))
    return cmds


def kv_table(rows: list[tuple[str, str]], key_w: float = 42 * mm, width: float = CONTENT_W) -> Table:
    data = [[Paragraph(esc(k), ST["kv_key"]), para(v, ST["kv_val"])] for k, v in rows]
    t = Table(data, colWidths=[key_w, width - key_w], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
    ]))
    return t


def callout(markup: str, color=ACCENT, bg=colors.HexColor("#eef2ff")) -> Table:
    t = Table([[para(markup, ST["body"])]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("LINEBEFORE", (0, 0), (0, -1), 2.5, color),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return t


# ─────────────────────────────────────────
# Report data helpers
# ─────────────────────────────────────────

def test_outcome(t: dict) -> str:
    if t.get("skipped") or t.get("passed") is None:
        return "skipped"
    return "passed" if t.get("passed") else "failed"


def severity_counts(findings: list) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        counts[sev if sev in counts else "INFO"] += 1
    return counts


def overall_risk(counts: dict) -> str:
    return next((s for s in SEVERITIES[:4] if counts.get(s)), "NONE")


def sorted_findings(findings: list) -> list:
    return sorted(findings, key=lambda f: (
        SEV_RANK.get(str(f.get("severity", "")).upper(), 9),
        CONF_RANK.get(str(f.get("confidence", "")).upper(), 9),
        f.get("endpoint", ""), f.get("method", ""),
    ))


def test_counts(results: list) -> dict:
    c = {"passed": 0, "failed": 0, "skipped": 0}
    for r in results:
        for t in r.get("tests", []):
            c[test_outcome(t)] += 1
    c["total"] = sum(c.values())
    return c


def deployment_ran(dep: dict) -> bool:
    return dep.get("status") not in (None, "unreachable", "unknown", "error")


# ─────────────────────────────────────────
# Page decoration
# ─────────────────────────────────────────

class NumberedCanvas(rl_canvas.Canvas):
    """Adds 'Page n of N' to every page except the cover."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pages = []

    def showPage(self):
        self._pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._pages)
        for state in self._pages:
            self.__dict__.update(state)
            if self._pageNumber > 1:
                self.setFont("Helvetica", 7.5)
                self.setFillColor(MUTED)
                self.drawRightString(PAGE_W - MARGIN_X, 11 * mm, f"Page {self._pageNumber} of {total}")
            super().showPage()
        super().save()


def _draw_cover(c: rl_canvas.Canvas, doc) -> None:
    c.saveState()
    band_h = doc.cover_band_h
    c.setFillColor(NAVY)
    c.rect(0, PAGE_H - band_h, PAGE_W, band_h, stroke=0, fill=1)
    c.setFillColor(ACCENT)
    c.rect(0, PAGE_H - band_h - 2.2 * mm, PAGE_W, 2.2 * mm, stroke=0, fill=1)
    # footer
    c.setStrokeColor(LINE)
    c.line(MARGIN_X, 22 * mm, PAGE_W - MARGIN_X, 22 * mm)
    c.setFont("Helvetica-Bold", 7.5)
    c.setFillColor(INK)
    c.drawString(MARGIN_X, 16.5 * mm, "CONFIDENTIAL")
    c.setFont("Helvetica", 7.5)
    c.setFillColor(MUTED)
    c.drawString(MARGIN_X + 21 * mm, 16.5 * mm,
                 "This report describes security weaknesses of the target API. Share it only with people who need it.")
    c.drawString(MARGIN_X, 12 * mm, f"Generated by {APP_NAME} on {doc.generated_label}")
    c.restoreState()


def _draw_body(c: rl_canvas.Canvas, doc) -> None:
    c.saveState()
    top = PAGE_H - 12 * mm
    c.setFont("Helvetica-Bold", 7.5)
    c.setFillColor(INK)
    c.drawString(MARGIN_X, top, APP_NAME.upper())
    c.setFont("Helvetica", 7.5)
    c.setFillColor(MUTED)
    c.drawString(MARGIN_X + c.stringWidth(APP_NAME.upper(), "Helvetica-Bold", 7.5) + 6,
                 top, "API Security Assessment")
    c.drawRightString(PAGE_W - MARGIN_X, top, clean(doc.api_label)[:90])
    c.setStrokeColor(LINE)
    c.setLineWidth(0.6)
    c.line(MARGIN_X, top - 3 * mm, PAGE_W - MARGIN_X, top - 3 * mm)
    c.line(MARGIN_X, 15 * mm, PAGE_W - MARGIN_X, 15 * mm)
    c.drawString(MARGIN_X, 11 * mm, "Confidential")
    c.restoreState()


# ─────────────────────────────────────────
# Sections
# ─────────────────────────────────────────

def _scan_option_rows(report: dict) -> list[tuple[str, str]]:
    opts  = report.get("scan_options") or {}
    usage = report.get("llm_usage") or {}

    safe = opts.get("safe_mode", True)
    safe_txt = ("<b>On</b> - DELETE, PUT and PATCH requests were not sent to the target"
                if safe else "<b>Off</b> - all documented methods, including DELETE/PUT/PATCH, were exercised")
    if opts.get("authenticated"):
        kind = AUTH_LABELS.get(opts.get("auth_type"), "Credential")
        auth_txt = f"<b>{esc(kind)}</b> - authenticated scan (the credential is not stored in this report)"
    else:
        auth_txt = "<b>None</b> - unauthenticated scan"

    stages = [("planner", "planning"), ("test_generation", "test generation"),
              ("deep_scan", "deep scan"), ("llm_analysis", "analysis")]
    used = [label for key, label in stages if usage.get(key)]
    ai_txt = ("Used for " + ", ".join(used)) if used else "Not used - rule-based checks only"
    if report.get("deep_scan_performed"):
        n = (report.get("deep_scan_summary") or {}).get("findings_enriched", 0)
        ai_txt += f"<br/>Deep scan performed ({n} finding{'s' if n != 1 else ''} enriched with proof-of-concept detail)"
    return [("Safe mode", safe_txt), ("Authentication", auth_txt), ("AI assistance", ai_txt)]


def cover(scan: dict, report: dict, ctx: dict) -> list:
    counts, risk = ctx["counts"], ctx["risk"]
    tc, s = ctx["tests"], report.get("summary") or {}

    band = [
        Spacer(1, 16 * mm),
        Paragraph(f"{esc(APP_NAME.upper())}", ST["c_brand"]),
        Spacer(1, 22 * mm),
        Paragraph("API Security Assessment", ST["c_kicker"]),
        Spacer(1, 3 * mm),
        Paragraph(esc(ctx["title"][:90]), ST["c_title"]),
        Spacer(1, 3 * mm),
        Paragraph(esc(ctx["subtitle"]), ST["c_sub"]),
    ]

    risk_color = SEV_COLOR[risk]
    risk_word  = "No findings" if risk == "NONE" else risk.title()
    total      = sum(counts.values())
    headline = Table([[
        Table([[Paragraph(esc(risk_word.upper()), ParagraphStyle(
            "risk", parent=ST["badge"], fontSize=10, leading=12))]],
            colWidths=[34 * mm], rowHeights=[9 * mm],
            style=[("BACKGROUND", (0, 0), (-1, -1), risk_color), ("ROUNDEDCORNERS", [3, 3, 3, 3]),
                   ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]),
        para(f"<b>Overall risk</b><br/>{total} finding{'s' if total != 1 else ''} · "
             f"{tc['passed']}/{tc['total']} tests passed · "
             f"deployment score {esc(s.get('deployment_security_score', 'N/A'))}", ST["body"]),
    ]], colWidths=[40 * mm, CONTENT_W - 40 * mm], hAlign="LEFT")
    headline.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                  ("LEFTPADDING", (0, 0), (-1, -1), 0)]))

    details = [
        ("API", f"<b>{esc(ctx['title'])}</b>" + (f" &nbsp;v{esc(ctx['version'])}" if ctx["version"] else "")),
        ("Target URL", f'<font face="Courier">{esc(ctx["base_url"] or "not set")}</font>'),
        ("Specification", esc(scan.get("name") or "-")),
        ("Endpoints", esc(scan.get("endpoint_count") or len(report.get("api_test_results") or []))),
        ("Scan date", esc(fmt_date(ctx["scan_date"]))),
        ("Scan ID", f'<font face="Courier" size="8">{esc(scan.get("id", "-"))}</font>'),
    ]

    return [
        Indenter(left=-MARGIN_X, right=-MARGIN_X),
        _CoverBand(band, ctx["band_h"]),
        Indenter(left=MARGIN_X, right=MARGIN_X),
        Spacer(1, 12 * mm),
        headline,
        Spacer(1, 9 * mm),
        Paragraph("Scan details", ST["h2"]),
        kv_table(details),
        Spacer(1, 4 * mm),
        Paragraph("Scan options", ST["h2"]),
        kv_table(_scan_option_rows(report)),
    ]


class _CoverBand(Flowable):
    """Fixed-height, full-width block whose contents sit on the navy band."""

    def __init__(self, flowables: list, height: float):
        super().__init__()
        self.flowables, self.height = flowables, height

    def wrap(self, avail_w, avail_h):
        self.width = avail_w
        return avail_w, self.height

    def draw(self):
        y = self.height
        inner_w = self.width - 2 * MARGIN_X
        for f in self.flowables:
            _, h = f.wrap(inner_w, y)
            y -= h
            f.drawOn(self.canv, MARGIN_X, y)


def executive_summary(scan: dict, report: dict, ctx: dict) -> list:
    counts, risk, tc = ctx["counts"], ctx["risk"], ctx["tests"]
    s   = report.get("summary") or {}
    dep = report.get("deployment") or {}
    total = sum(counts.values())

    # Narrative
    sev_parts = [f"{counts[k]} {k.lower()}" for k in SEVERITIES if counts.get(k)]
    if total:
        finding_txt = (f"The scan identified <b>{total} potential security finding{'s' if total != 1 else ''}</b> "
                       f"({', '.join(sev_parts)}); the highest severity is <b>{risk.lower()}</b>.")
    else:
        finding_txt = "The scan identified <b>no security findings</b>."
    rate = f" ({round(100 * tc['passed'] / tc['total'])}%)" if tc["total"] else ""
    test_txt = (f"<b>{tc['passed']} of {tc['total']}</b> API tests passed{rate}, {tc['failed']} failed"
                + (f" and {tc['skipped']} were skipped" if tc["skipped"] else "") + ".")
    if deployment_ran(dep):
        dep_txt = (f"The deployment is <b>{esc(dep.get('status'))}</b> and scored "
                   f"<b>{esc(dep.get('security_score', 'N/A'))}</b> on transport and header checks.")
    else:
        dep_txt = "Deployment checks could not be run against the target."
    intro = (f"{APP_NAME} scanned <b>{esc(ctx['title'])}</b> at "
             f'<font face="Courier">{esc(ctx["base_url"] or "an unspecified target")}</font> '
             f"on {esc(fmt_date(ctx['scan_date']))}. {finding_txt} {test_txt} {dep_txt}")

    # KPI tiles
    def tile(num_markup, label, sub, color=INK):
        return [Paragraph(label.upper(), ST["kpi_lbl"]),
                Paragraph(f'<font color="{_hex(color)}">{num_markup}</font>', ST["kpi_num"]),
                Paragraph(sub, ST["kpi_sub"])]

    risk_word = "None" if risk == "NONE" else risk.title()
    tiles = [
        tile(esc(risk_word), "Overall risk", "highest finding severity", SEV_COLOR[risk]),
        tile(str(total), "Security findings",
             f"{counts['CRITICAL'] + counts['HIGH']} critical/high" if total else "nothing flagged"),
        tile(f"{tc['passed']}/{tc['total']}", "Tests passed",
             f"{tc['failed']} failed" + (f", {tc['skipped']} skipped" if tc["skipped"] else ""),
             PASS if tc["total"] and not tc["failed"] else INK),
        tile(esc(s.get("deployment_security_score", "N/A")), "Deployment score",
             esc(dep.get("status", "not run"))),
    ]
    tile_w = CONTENT_W / 4
    kpis = Table([tiles], colWidths=[tile_w] * 4)
    kpis.setStyle(TableStyle([
        ("BOX", (0, 0), (0, 0), 0.6, LINE), ("BOX", (1, 0), (1, 0), 0.6, LINE),
        ("BOX", (2, 0), (2, 0), 0.6, LINE), ("BOX", (3, 0), (3, 0), 0.6, LINE),
        ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
        ("LINEABOVE", (0, 0), (0, 0), 2.5, SEV_COLOR[risk]),
        ("LINEABOVE", (1, 0), (-1, 0), 2.5, ACCENT),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("LEFTPADDING", (0, 0), (-1, -1), 9), ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))

    # Severity breakdown with bars
    max_n = max(counts.values()) if counts else 0
    bar_w = 70 * mm
    sev_rows = [[Paragraph("SEVERITY", ST["th"]), Paragraph("COUNT", ST["th"]), Paragraph("", ST["th"])]]
    for sev in SEVERITIES[:4] + (["INFO"] if counts.get("INFO") else []):
        sev_rows.append([badge(sev, SEV_COLOR[sev]),
                         Paragraph(f"<b>{counts[sev]}</b>", ST["cell"]),
                         Bar(counts[sev], max_n, SEV_COLOR[sev], bar_w)])
    sev_table = Table(sev_rows, colWidths=[24 * mm, 16 * mm, bar_w + 6], hAlign="LEFT")
    sev_table.setStyle(TableStyle(grid_style(zebra=False) + [("VALIGN", (0, 1), (-1, -1), "MIDDLE")]))

    # Test outcomes
    test_rows = [[Paragraph(h, ST["th"]) for h in ("OUTCOME", "TESTS", "")]]
    for key, color in (("passed", PASS), ("failed", FAIL), ("skipped", SKIP)):
        test_rows.append([badge(key.upper(), color), Paragraph(f"<b>{tc[key]}</b>", ST["cell"]),
                          Bar(tc[key], tc["total"], color, bar_w)])
    test_table = Table(test_rows, colWidths=[24 * mm, 16 * mm, bar_w + 6], hAlign="LEFT")
    test_table.setStyle(TableStyle(grid_style(zebra=False) + [("VALIGN", (0, 1), (-1, -1), "MIDDLE")]))

    out = section("Executive summary", 1) + [
        para(intro, ST["body"]), Spacer(1, 4 * mm), kpis, Spacer(1, 2 * mm),
        KeepTogether([Paragraph("Findings by severity", ST["h2"]), sev_table]),
        KeepTogether([Paragraph("API test outcomes", ST["h2"]), test_table]),
    ]

    plan = report.get("planner_assessment") or {}
    if plan.get("risk_summary"):
        auth = plan.get("auth_pattern_detected")
        txt = md_inline(plan["risk_summary"])
        if auth:
            txt += f"<br/><font color=\"{_hex(MUTED)}\">Authentication pattern detected: {esc(auth)}</font>"
        out += [KeepTogether([Paragraph("Risk assessment (AI planner)", ST["h2"]), callout(txt)])]

        hot = plan.get("high_risk_endpoints") or []
        if hot:
            rows = [[Paragraph(h, ST["th"]) for h in ("ENDPOINT", "PLANNER RISK", "WHY")]]
            for ep in hot[:8]:
                lvl = str(ep.get("risk_level", "")).upper()
                reasons = "; ".join(clean(r) for r in (ep.get("risk_reasons") or [])[:2])
                rows.append([
                    para(f'<font face="Courier"><b>{esc(ep.get("method", ""))}</b> {esc(ep.get("path", ""))}</font>',
                         ST["cell"]),
                    badge(lvl or "-", SEV_COLOR.get(lvl, SKIP)),
                    para(esc(reasons), ST["cell"]),
                ])
            t = Table(rows, colWidths=[52 * mm, 24 * mm, CONTENT_W - 76 * mm], repeatRows=1)
            t.setStyle(TableStyle(grid_style()))
            out += [Spacer(1, 3 * mm), Paragraph("Highest-risk endpoints (AI planner)", ST["h3"]), t]
    return out


def findings_section(report: dict) -> list:
    findings = sorted_findings(report.get("security_findings") or [])
    out = section("Security findings", 2)
    if not findings:
        return out + [Paragraph("No security findings were reported for this scan.", ST["body"])]

    out.append(Paragraph(
        "Findings are sorted by severity, then confidence. <b>Static</b> findings are inferred from the "
        "OpenAPI specification; <b>dynamic</b> findings were observed in live responses from the target.",
        ST["muted"]))
    out.append(Spacer(1, 3 * mm))

    head = [Paragraph(h, ST["th"]) for h in ("#", "SEVERITY", "FINDING", "ENDPOINT", "CONFIDENCE", "DETECTION")]
    rows = [head]
    for i, f in enumerate(findings, 1):
        sev = str(f.get("severity", "INFO")).upper()
        name = clean(f.get("vulnerability") or f.get("risk_type") or "Finding")
        desc = f.get("description") or ""
        finding_cell = [para(f"<b>{esc(name)}</b>", ST["cellb"])]
        if desc:
            finding_cell.append(para(esc(desc), ST["muted"]))
        det = str(f.get("detection_type") or "-").title()
        if f.get("confirmed"):
            det += '<br/><font color="#b42318"><b>Confirmed</b></font>'
        conf = str(f.get("confidence") or "-").title()
        rows.append([
            Paragraph(str(i), ST["cell"]),
            badge(sev, SEV_COLOR.get(sev, SKIP)),
            finding_cell,
            para(f'<font face="Courier"><b>{esc(f.get("method", ""))}</b><br/>{esc(f.get("endpoint", ""))}</font>',
                 ST["cell"]),
            Paragraph(esc(conf), ST["cell"]),
            para(det, ST["cell"]),
        ])
    widths = [7 * mm, 21 * mm, 67 * mm, 35 * mm, 24 * mm]
    widths.append(CONTENT_W - sum(widths))
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle(grid_style()))
    out.append(t)

    pocs = [(i, f) for i, f in enumerate(findings, 1) if f.get("exploit_poc")]
    if pocs:
        # Heading travels with the first block so it is never left alone at a page bottom
        intro = [Paragraph("Proof-of-concept details", ST["h2"]),
                 Paragraph("Produced by the deep scan for the most serious findings. Requests are illustrative; "
                           "run them only against systems you are authorised to test.", ST["muted"]),
                 Spacer(1, 2 * mm)]
        out.append(Spacer(1, 4 * mm))
        for n, (i, f) in enumerate(pocs):
            parts = _poc_block(i, f)
            out.append(KeepTogether(intro + parts if n == 0 else parts))
    return out


def _poc_block(i: int, f: dict) -> list:
    poc = f["exploit_poc"]
    sev = str(f.get("severity", "INFO")).upper()
    source = "AI-generated" if poc.get("generated_by") == "llm" else "Rule-based"
    title = (f"#{i} &nbsp;{esc(f.get('vulnerability') or f.get('risk_type'))} &nbsp;"
             f'<font face="Courier" color="{_hex(MUTED)}">{esc(f.get("method", ""))} {esc(f.get("endpoint", ""))}</font>')
    parts = [
        Table([[badge(sev, SEV_COLOR.get(sev, SKIP)), para(title, ST["h3"]),
                Paragraph(esc(source), ST["right"])]],
              colWidths=[20 * mm, CONTENT_W - 48 * mm, 28 * mm],
              style=[("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]),
    ]
    if poc.get("summary"):
        parts.append(para(esc(poc["summary"]), ST["body"]))
    steps = poc.get("steps") or []
    for n, step in enumerate(steps, 1):
        step = re.sub(r"^\s*step\s*\d+\s*[:.)-]\s*", "", clean(step), flags=re.I)
        parts.append(para(md_inline(step), ST["bullet"], bulletText=f"{n}."))

    def code_box(label, text):
        lines = escape(clean(text)).replace("\n", "<br/>")
        box = Table([[Paragraph(label.upper(), ST["th"])], [para(lines, ST["code"])]], colWidths=[CONTENT_W])
        box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), SURFACE), ("BOX", (0, 0), (-1, -1), 0.5, LINE),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ]))
        return box

    if poc.get("sample_curl"):
        parts += [Spacer(1, 2), code_box("Sample request", poc["sample_curl"])]
    if poc.get("expected_vulnerable_response"):
        parts += [Spacer(1, 4), code_box("Expected vulnerable response", poc["expected_vulnerable_response"])]
    if poc.get("verification_test"):
        parts += [Spacer(1, 4), para(f"<b>Verify the fix:</b> {md_inline(poc['verification_test'])}", ST["body"])]
    parts += [HRFlowable(width="100%", thickness=0.5, color=LINE, spaceBefore=4, spaceAfter=8)]
    return parts


def _test_row(t: dict, base_url: str) -> list:
    outcome = test_outcome(t)
    name = t.get("test", "test")
    req  = t.get("request") or {}

    if name == "skipped_safe_mode":
        return [Paragraph("All tests", ST["cell"]), Paragraph("-", ST["cell"]),
                para(esc(t.get("note") or "Not sent in safe mode"), ST["cell"]),
                Paragraph("-", ST["cell"]), badge("SKIPPED", SKIP), "safe"]

    if "total_payloads" in t:                               # dynamic fuzzing summary
        flagged = t.get("vulnerable_count", 0)
        request = f"{t.get('total_payloads', 0)} payloads"
        expected = "No injection indicators"
        status = f"{flagged} flagged" if flagged else "none flagged"
    else:
        request = (f'<font face="Courier">{esc(req.get("method", ""))} '
                   f'{esc(short_url(req.get("url", ""), base_url))}</font>') if req else "-"
        expected = esc(t.get("expected", "-"))
        if t.get("status_code") is not None:
            status = str(t["status_code"])
        elif t.get("error"):
            status = '<font color="#667085">no response</font>'
        else:
            status = "-"

    label = {"passed": ("PASS", PASS), "failed": ("FAIL", FAIL), "skipped": ("SKIPPED", SKIP)}[outcome]
    name_cell = [Paragraph(esc(humanize(name)), ST["cell"])]
    if t.get("error") and outcome == "skipped":
        name_cell.append(para(esc(str(t["error"])[:140]), ST["muted"]))
    return [name_cell, para(request, ST["cell"]), para(expected, ST["cell"]),
            para(status, ST["cell"]), badge(*label), outcome]


def tests_section(report: dict, ctx: dict) -> list:
    results = report.get("api_test_results") or []
    tc = ctx["tests"]
    out = section("API tests", 3)
    if not results:
        return out + [Paragraph("No API tests were run for this scan (no reachable target URL).", ST["body"])]

    out.append(para(
        f"{len(results)} endpoint{'s' if len(results) != 1 else ''} tested · "
        f"<b>{tc['passed']}</b> passed, <b>{tc['failed']}</b> failed, <b>{tc['skipped']}</b> skipped. "
        "Each endpoint gets a valid request, input-validation and method checks and payload fuzzing; "
        "<i>Expected</i> is what a well-behaved API should return.", ST["muted"]))
    out.append(Spacer(1, 3 * mm))

    widths = [38 * mm, 52 * mm, 38 * mm, 20 * mm]
    widths.append(CONTENT_W - sum(widths))
    for r in results:
        tests = r.get("tests") or []
        rows_data = [_test_row(t, r.get("base_url") or ctx["base_url"]) for t in tests]
        passed = sum(1 for row in rows_data if row[5] == "passed")
        counted = sum(1 for row in rows_data if row[5] != "skipped" and row[5] != "safe")
        auth = ' &nbsp;<font color="#667085" size="7.5">requires auth</font>' if r.get("requires_auth") else ""
        summary = (f"{passed}/{counted} passed" if counted else "skipped")
        any_fail = any(row[5] == "failed" for row in rows_data)

        title_row = [para(f'<font face="Courier"><b>{esc(r.get("method", ""))}</b> {esc(r.get("endpoint", ""))}</font>{auth}',
                          ST["cellb"]), "", "", "",
                     para(f'<font color="{_hex(FAIL if any_fail else PASS if counted else SKIP)}"><b>{summary}</b></font>',
                          ST["right"])]
        head = [Paragraph(h, ST["th"]) for h in ("TEST", "REQUEST", "EXPECTED", "STATUS", "RESULT")]
        rows = [title_row, head] + [row[:5] for row in rows_data]
        if not rows_data:
            rows.append([Paragraph("No tests were recorded for this endpoint.", ST["muted"]), "", "", "", ""])
        t = Table(rows, colWidths=widths, repeatRows=2)
        t.setStyle(TableStyle(grid_style(header_rows=2) + [
            ("SPAN", (0, 0), (3, 0)),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f4f7")),
            ("BACKGROUND", (0, 1), (-1, 1), colors.white),
            ("LINEABOVE", (0, 0), (-1, 0), 1.2, FAIL if any_fail else ACCENT),
            ("VALIGN", (0, 0), (-1, 0), "MIDDLE"),
        ]))
        out += [KeepTogether([t]) if len(rows) <= 14 else t, Spacer(1, 5 * mm)]
    return out


def deployment_section(report: dict) -> list:
    dep = report.get("deployment") or {}
    out = section("Deployment checks", 4)
    if not deployment_ran(dep):
        reason = dep.get("error") or dep.get("reason") or "the target URL was not set or did not respond"
        return out + [callout(f"<b>Deployment checks were not run.</b> {esc(reason)}",
                              FAIL, FAIL_BG)]

    def yes_no(value: bool, good_when: bool, yes="Yes", no="No"):
        ok = value == good_when
        color = PASS if ok else FAIL
        return f'<font color="{_hex(color)}"><b>{yes if value else no}</b></font>'

    latency = dep.get("latency_ms")
    docs_txt = yes_no(bool(dep.get("docs_exposed")), False)
    if dep.get("docs_exposed") and dep.get("docs_exposed_at"):
        docs_txt += f' &nbsp;<font face="Courier" size="8">{esc(dep["docs_exposed_at"])}</font>'
    facts = [
        ("Status", f"<b>{esc(dep.get('status', '-'))}</b>"
                   + (f" &nbsp;(HTTP {esc(dep['status_code'])})" if dep.get("status_code") else "")),
        ("Response time", f"{latency:.0f} ms" if isinstance(latency, (int, float)) else "-"),
        ("HTTPS enforced", yes_no(bool(dep.get("https_enforced")), True)),
        ("CORS misconfigured", yes_no(bool(dep.get("cors_misconfigured")), False)),
        ("API docs publicly exposed", docs_txt),
        ("Security score", f"<b>{esc(dep.get('security_score', 'N/A'))}</b>"),
    ]
    out.append(kv_table(facts, key_w=50 * mm))

    headers = dep.get("security_headers") or {}
    present, missing = headers.get("present") or [], headers.get("missing") or []
    if present or missing:
        rows = [[Paragraph(h, ST["th"]) for h in ("SECURITY HEADER", "STATUS")]]
        for h in present:
            rows.append([para(f'<font face="Courier">{esc(h)}</font>', ST["cell"]), badge("PRESENT", PASS)])
        for h in missing:
            rows.append([para(f'<font face="Courier">{esc(h)}</font>', ST["cell"]), badge("MISSING", FAIL)])
        t = Table(rows, colWidths=[70 * mm, 24 * mm], hAlign="LEFT")
        t.setStyle(TableStyle(grid_style() + [("VALIGN", (0, 1), (-1, -1), "MIDDLE")]))
        out += [KeepTogether([Paragraph(f"Security headers &nbsp;<font color=\"{_hex(MUTED)}\" size=\"9\">"
                                        f"{len(present)} of {len(present) + len(missing)} present</font>",
                                        ST["h2"]), t])]

    other = [f for f in dep.get("deployment_findings") or []
             if not str(f.get("check", "")).startswith("security_header:")]
    if other:
        out.append(Paragraph("Other deployment issues", ST["h2"]))
        for f in other:
            out.append(para(esc(f.get("issue") or f.get("check")), ST["bullet"], bulletText="•"))
    return out


def recommendations_section(report: dict) -> list:
    recs = report.get("recommendations") or []
    out = section("Recommendations", 5)
    if not recs:
        return out + [Paragraph("No recommendations.", ST["body"])]
    rows = []
    for i, r in enumerate(recs, 1):
        rows.append([Paragraph(f'<font color="{_hex(ACCENT)}"><b>{i:02d}</b></font>', ST["body"]),
                     para(md_inline(r), ST["body"])])
    t = Table(rows, colWidths=[11 * mm, CONTENT_W - 11 * mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    return out + [t]


def analysis_section(report: dict) -> list:
    text = (report.get("llm_analysis") or "").strip()
    used = (report.get("llm_usage") or {}).get("llm_analysis")
    out = section("AI analysis", 6)
    if not text:
        return out + [Paragraph("No analysis was produced for this scan.", ST["body"])]
    note = ("Written by a large language model from the findings above. Review it before acting on it."
            if used else "The language model was unavailable for this scan; this is the rule-based summary.")
    return out + [Paragraph(note, ST["muted"]), Spacer(1, 3 * mm)] + markdown_flowables(text)


# ─────────────────────────────────────────
# Minimal markdown renderer (for the AI analysis)
# ─────────────────────────────────────────

_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")
_BULLET    = re.compile(r"^(\s*)[-*+]\s+(.*)$")
_NUMBERED  = re.compile(r"^(\s*)(\d+)[.)]\s+(.*)$")
_HEADING   = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_RULE      = re.compile(r"^\s*([-*_])(\s*\1){2,}\s*$")


def _md_table(lines: list[str]) -> Table:
    rows = []
    for line in lines:
        if _TABLE_SEP.match(line):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        rows.append(cells)
    ncol = max(len(r) for r in rows)
    rows = [r + [""] * (ncol - len(r)) for r in rows]

    lengths = []
    for c in range(ncol):
        longest = max(len(_strip_tags(md_inline(r[c]))) for r in rows)
        lengths.append(min(max(longest, 3), 90) ** 0.75)
    widths = [CONTENT_W * w / sum(lengths) for w in lengths]

    data = [[para(md_inline(c), ST["th"] if i == 0 else ST["cell"]) for c in r] for i, r in enumerate(rows)]
    t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle(grid_style()))
    return t


def markdown_flowables(md: str) -> list:
    out: list = []
    lines = clean(md).replace("\r\n", "\n").split("\n")
    buf: list[str] = []

    def flush():
        if buf:
            text = ""
            for j, line in enumerate(buf):
                hard = line.endswith("  ") or line.endswith("\\")
                text += md_inline(line.rstrip(" \\"))
                if j < len(buf) - 1:
                    text += "<br/>" if hard else " "
            out.append(para(text, ST["body"]))
            buf.clear()

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            flush()
        elif stripped.startswith("|"):
            flush()
            block = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                block.append(lines[i])
                i += 1
            out += [Spacer(1, 2), _md_table(block), Spacer(1, 8)]
            continue
        elif _RULE.match(stripped):
            flush()
            out.append(HRFlowable(width="100%", thickness=0.6, color=LINE, spaceBefore=6, spaceAfter=8))
        elif m := _HEADING.match(stripped):
            flush()
            style = ST["h2"] if len(m.group(1)) <= 2 else ST["h3"]
            out.append(CondPageBreak(25 * mm))
            out.append(para(md_inline(m.group(2)), style))
        elif (m := _BULLET.match(line)) or (m2 := _NUMBERED.match(line)):
            flush()
            if m:
                indent, bullet, text = len(m.group(1)), "•", m.group(2)
            else:
                indent, bullet, text = len(m2.group(1)), f"{m2.group(2)}.", m2.group(3)
            # continuation lines indented under the item
            while (i + 1 < len(lines) and lines[i + 1].startswith("  ") and lines[i + 1].strip()
                   and not _BULLET.match(lines[i + 1]) and not _NUMBERED.match(lines[i + 1])):
                i += 1
                text += " " + lines[i].strip()
            level = min(indent // 2, 3)
            style = ParagraphStyle(f"li{level}", parent=ST["bullet"],
                                   leftIndent=14 + 12 * level, bulletIndent=3 + 12 * level)
            out.append(para(md_inline(text.rstrip()), style, bulletText=bullet))
        else:
            buf.append(line.rstrip("\n"))
        i += 1
    flush()
    return out


# ─────────────────────────────────────────
# Entry points
# ─────────────────────────────────────────

def report_pdf_filename(scan: dict) -> str:
    report = scan.get("report") or {}
    date = (report.get("generated_at") or scan.get("created_at") or "")[:10] or "undated"
    return f"api-sentinel-{slug(scan.get('api_title') or 'api')}-{date}.pdf"


def build_report_pdf(scan: dict) -> bytes:
    """Render a scan row (with its `report`) to PDF bytes."""
    report = scan.get("report") or {}
    parsed = scan.get("parsed_data") or {}
    findings = report.get("security_findings") or []
    results  = report.get("api_test_results") or []

    base_url = parsed.get("base_url") or next((r.get("base_url") for r in results if r.get("base_url")), "")
    title    = clean(scan.get("api_title") or parsed.get("title") or "Untitled API")
    version  = clean(scan.get("api_version") or parsed.get("version") or "")
    counts   = severity_counts(findings)
    ctx = {
        "title":     title,
        "version":   version,
        "base_url":  base_url,
        "scan_date": report.get("generated_at") or scan.get("created_at"),
        "counts":    counts,
        "risk":      overall_risk(counts),
        "tests":     test_counts(results),
        "band_h":    112 * mm,
        "subtitle":  (f"Version {version}  ·  " if version else "") + (base_url or "target URL not set"),
    }

    buf = BytesIO()
    doc = BaseDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN_X, rightMargin=MARGIN_X, topMargin=22 * mm, bottomMargin=22 * mm,
        title=f"API Security Assessment - {title}", author=APP_NAME,
        subject=f"Security scan of {base_url or title}", creator=APP_NAME,
    )
    doc.cover_band_h    = ctx["band_h"]
    doc.generated_label = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    doc.api_label       = title + (f" v{version}" if version else "")

    cover_frame = Frame(MARGIN_X, 26 * mm, CONTENT_W, PAGE_H - 26 * mm, id="cover",
                        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    body_frame = Frame(MARGIN_X, 20 * mm, CONTENT_W, PAGE_H - 42 * mm, id="body",
                       leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[cover_frame], onPage=_draw_cover),
        PageTemplate(id="body", frames=[body_frame], onPage=_draw_body),
    ])

    story: list = cover(scan, report, ctx)
    story += [NextPageTemplate("body"), PageBreak()]
    story += executive_summary(scan, report, ctx)
    story += [PageBreak()] + findings_section(report)
    story += [PageBreak()] + tests_section(report, ctx)
    story += [PageBreak()] + deployment_section(report)
    story += [Spacer(1, 6 * mm)] + recommendations_section(report)
    story += [PageBreak()] + analysis_section(report)

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()
