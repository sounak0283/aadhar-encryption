"""
audit_pdf_service.py
Renders the date-range audit report (app.services.audit_report_service) as a
PDF, in the same layout as the source spreadsheet: a From Date / To Date
header, then one row per (date, hit) — every submit and decrypt attempt
against a record, each with its own timestamp, including a blank row for any
date in range with zero hits — across whichever of Date, Reference ID,
Masked Aadhaar No, and Request Datetime the caller selects (default: all
four). Only already-masked metadata is ever rendered here; this never touches
key material or the plaintext Aadhaar number.

Cell text is wrapped via Paragraph (not raw strings) specifically because
reference_id is a long, space-free hex string (44 chars) — a plain Table
cell doesn't wrap and silently overflows into the next column instead.
"""
import io
from datetime import date, datetime, timedelta, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.services import audit_report_service

_HEADER_BG = colors.HexColor("#1F2933")
_ROW_ALT_BG = colors.HexColor("#F5F6F8")
_GRID_COLOR = colors.HexColor("#CBD2D9")
_META_COLOR = colors.HexColor("#444444")


class InvalidColumnError(Exception):
    """Raised when the caller asks for an unknown PDF column."""


_IST = timezone(timedelta(hours=5, minutes=30))  # fixed offset — IST has no DST, so no tzdata dependency needed


def _fmt_date(iso_date: str) -> str:
    y, m, d = iso_date.split("-")
    return f"{d}-{m}-{y}"


def _fmt_datetime(value: datetime | None) -> str:
    """Renders in IST, not the UTC the value is stored/passed in as — this is
    a fixed export document, not a browser that can localize itself, and
    every admin using this system is in India."""
    if value is None:
        return ""
    return value.astimezone(_IST).strftime("%d-%m-%Y %H:%M:%S")


# Column definitions: header label, rendered width, and how to pull the cell
# value out of an audit_report_service row. Widths were chosen so the default
# (all four) sums to 212mm, comfortably inside landscape A4's ~269mm usable
# width (297mm page minus 14mm side margins) — Reference ID gets the most
# room since it's a 44-character hex string.
_COLUMN_DEFS: dict[str, dict] = {
    "date": {"header": "Date", "width": 26 * mm, "value": lambda row: _fmt_date(row["date"])},
    "reference_id": {"header": "Reference ID", "width": 90 * mm, "value": lambda row: row["reference_id"] or ""},
    "masked_aadhaar_no": {
        "header": "Masked Aadhaar No",
        "width": 46 * mm,
        "value": lambda row: row["masked_aadhaar_no"] or "",
    },
    "request_datetime": {
        "header": "Request Datetime (IST)",
        "width": 50 * mm,
        "value": lambda row: _fmt_datetime(row["request_datetime"]),
    },
}
DEFAULT_COLUMNS = ["date", "reference_id", "masked_aadhaar_no", "request_datetime"]

_styles = getSampleStyleSheet()
_HEADER_CELL_STYLE = ParagraphStyle(
    "AuditHeaderCell", parent=_styles["Normal"], fontName="Helvetica-Bold", fontSize=8.5,
    textColor=colors.white, leading=10,
)
_BODY_CELL_STYLE = ParagraphStyle(
    "AuditBodyCell", parent=_styles["Normal"], fontName="Courier", fontSize=7.5, leading=9,
)


def _header_cell(text: str) -> Paragraph:
    return Paragraph(text, _HEADER_CELL_STYLE)


def _body_cell(text: str) -> Paragraph:
    return Paragraph(text, _BODY_CELL_STYLE)


async def generate_pdf(from_date: date, to_date: date, columns: list[str] | None = None) -> bytes:
    selected = DEFAULT_COLUMNS if columns is None else columns
    unknown = [c for c in selected if c not in _COLUMN_DEFS]
    if unknown:
        raise InvalidColumnError(f"unknown column(s): {', '.join(unknown)}")
    if not selected:
        raise InvalidColumnError("at least one column must be selected")

    rows = await audit_report_service.generate_report(from_date, to_date)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        topMargin=16 * mm,
        bottomMargin=14 * mm,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        title="Aadhaar Submission Audit Report",
    )

    title_style = ParagraphStyle("AuditTitle", parent=_styles["Heading1"], fontSize=15, spaceAfter=2, alignment=TA_LEFT)
    meta_style = ParagraphStyle("AuditMeta", parent=_styles["Normal"], fontSize=10, textColor=_META_COLOR)

    elements = [
        Paragraph("Aadhaar Submission Audit Report", title_style),
        Paragraph(
            f"From Date: {_fmt_date(from_date.isoformat())} &nbsp;&nbsp;&nbsp;&nbsp; "
            f"To Date: {_fmt_date(to_date.isoformat())}",
            meta_style,
        ),
        Spacer(1, 6 * mm),
    ]

    col_defs = [_COLUMN_DEFS[key] for key in selected]
    header_row = [_header_cell(col["header"]) for col in col_defs]
    table_data = [header_row]
    for row in rows:
        table_data.append([_body_cell(col["value"](row)) for col in col_defs])

    table = Table(table_data, colWidths=[col["width"] for col in col_defs], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _ROW_ALT_BG]),
                ("GRID", (0, 0), (-1, -1), 0.4, _GRID_COLOR),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    elements.append(table)

    doc.build(elements)
    return buffer.getvalue()
