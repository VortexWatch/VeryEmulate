"""
hexview.py — Minimal, dependency-free hex viewer widget for diagnostics.
Displays classic 16-bytes-per-row hex + ASCII gutter, using a monospace
QPlainTextEdit for simplicity/robustness (no custom paint code, so it can
never crash on odd-sized or huge buffers — content is simply chunked and
capped).
"""
from __future__ import annotations
from PySide6.QtWidgets import QPlainTextEdit
from PySide6.QtGui import QFont

MAX_BYTES_DISPLAYED = 64 * 1024  # cap to keep the widget responsive


def format_hex_dump(data: bytes, base_offset: int = 0, max_bytes: int = MAX_BYTES_DISPLAYED) -> str:
    lines = []
    truncated = len(data) > max_bytes
    view = data[:max_bytes]
    for i in range(0, len(view), 16):
        chunk = view[i:i + 16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(16 * 3 - 1)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{base_offset + i:08x}  {hex_part}  |{ascii_part}|')
    if truncated:
        lines.append(f"... truncated, showing first {max_bytes} of {len(data)} bytes ...")
    return '\n'.join(lines)


class HexView(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        f = QFont("Courier New")
        f.setStyleHint(QFont.Monospace)
        f.setPointSize(9)
        self.setFont(f)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)

    def show_bytes(self, data: bytes, base_offset: int = 0, title: str = ""):
        text = format_hex_dump(data, base_offset)
        if title:
            text = f"# {title}\n" + text
        self.setPlainText(text)
