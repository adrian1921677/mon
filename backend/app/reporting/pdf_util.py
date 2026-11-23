"""Minimal PDF writer (Helvetica) — no third-party PDF dependency."""

from __future__ import annotations


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def text_pdf(title: str, lines: list[str], *, page_width: int = 612, page_height: int = 792) -> bytes:
    """Render a multi-page text PDF suitable for local reports."""
    margin_x = 50
    margin_top = 72
    line_height = 14
    usable = page_height - margin_top - 50
    max_lines = max(1, usable // line_height)

    wrapped: list[str] = [title, ""]
    for raw in lines:
        text = (raw or "").replace("\t", " ")
        while len(text) > 95:
            wrapped.append(text[:95])
            text = text[95:]
        wrapped.append(text)

    pages: list[list[str]] = []
    for i in range(0, len(wrapped), max_lines):
        pages.append(wrapped[i : i + max_lines])
    if not pages:
        pages = [[title]]

    content_streams: list[bytes] = []
    for page_lines in pages:
        y = page_height - margin_top
        parts = ["BT", "/F1 11 Tf", f"{margin_x} {y} Td", "14 TL"]
        first = True
        for line in page_lines:
            esc = _escape(line)
            if first:
                parts.append(f"({esc}) Tj")
                first = False
            else:
                parts.append(f"T* ({esc}) Tj")
        parts.append("ET")
        content_streams.append("\n".join(parts).encode("latin-1", errors="replace"))

    font_obj_id = 3
    page_obj_ids: list[int] = []
    content_obj_ids: list[int] = []
    next_id = 4
    for _ in content_streams:
        page_obj_ids.append(next_id)
        content_obj_ids.append(next_id + 1)
        next_id += 2

    kids = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    objs: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {len(page_obj_ids)} >>".encode("ascii"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    for page_id, content_id, stream in zip(page_obj_ids, content_obj_ids, content_streams):
        assert page_id == len(objs) + 1
        objs.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page_width} {page_height}] "
                f"/Contents {content_id} 0 R /Resources << /Font << /F1 {font_obj_id} 0 R >> >> >>"
            ).encode("ascii")
        )
        objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out.extend(f"{i} 0 obj\n".encode("ascii"))
        out.extend(body)
        out.extend(b"\nendobj\n")
    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objs) + 1}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    out.extend(
        f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(out)
