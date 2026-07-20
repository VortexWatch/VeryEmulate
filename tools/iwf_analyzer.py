#!/usr/bin/env python3
"""
iwf_analyzer.py — Phase 1 reverse-engineering toolkit for VeryFit/IDW .iwf watch face files.

Provides:
  - IWFContainer: parses the .iwf container (magic + table-of-contents + blobs)
  - RawImage: decodes the proprietary "RAW\\0" RGB565(+4bpp alpha) image codec
  - signature_scan(): scans arbitrary binary blobs for known file signatures
    (PNG/JPEG/BMP/ZIP/RAW/JSON/XML) — used both on .iwf containers and raw
    firmware (.fw) images.
  - build_structure_map(): produces a JSON structure map of a parsed container
  - analyze(): produces a full human-readable analysis report

Run directly for a CLI report:
    python3 iwf_analyzer.py path/to/file.iwf
    python3 iwf_analyzer.py path/to/file.fw --scan-only
"""
from __future__ import annotations
import struct
import json
import os
import re
import sys
import zipfile
import io
from dataclasses import dataclass, field
from typing import Optional


# --------------------------------------------------------------------------
# Known binary signatures we scan for inside arbitrary blobs (used for both
# the .iwf container payloads and for probing the raw .fw firmware image).
# --------------------------------------------------------------------------
SIGNATURES = [
    (b'\x89PNG\r\n\x1a\n', 'PNG'),
    (b'\xff\xd8\xff', 'JPEG'),
    (b'BM', 'BMP (weak signature, verified by header sanity check)'),
    (b'PK\x03\x04', 'ZIP (local file header)'),
    (b'PK\x05\x06', 'ZIP (end of central directory)'),
    (b'RAW\x00', 'RAW proprietary image (IDW/VeryFit RGB565 codec)'),
    (b'iwf\x00', 'IWF container magic'),
]

TEXT_BLOCK_RE = re.compile(rb'[\x20-\x7e\r\n\t]{24,}')
JSON_START_RE = re.compile(rb'\{\s*"')


def signature_scan(data: bytes, min_bmp_header_sanity=True):
    """Scan a blob for known file signatures. Returns list of dicts:
    {offset, signature_name, hex_prefix}."""
    hits = []
    for sig, name in SIGNATURES:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break
            # BMP is a weak 2-byte signature ("BM"); only report it if the
            # bytes that follow look like a plausible BITMAPFILEHEADER
            # (reasonable file size field, reserved bytes zero).
            if sig == b'BM' and min_bmp_header_sanity:
                if idx + 14 <= len(data):
                    size_field = struct.unpack_from('<I', data, idx + 2)[0]
                    reserved = struct.unpack_from('<I', data, idx + 6)[0]
                    if reserved != 0 or size_field == 0 or size_field > len(data):
                        start = idx + 1
                        continue
            hits.append({
                'offset': idx,
                'signature': name,
                'hex_prefix': data[idx:idx + 16].hex(),
            })
            start = idx + 1
    hits.sort(key=lambda h: h['offset'])
    return hits


def find_text_json_blocks(data: bytes, max_blocks=200):
    """Find likely JSON/text blocks in a blob (best-effort, offset-based)."""
    blocks = []
    for m in JSON_START_RE.finditer(data):
        start = m.start()
        # Try to find matching closing brace by attempting incremental JSON
        # parses; cheap heuristic: search forward for a brace-balanced region.
        depth = 0
        end = None
        in_str = False
        esc = False
        for i in range(start, min(len(data), start + 200000)):
            c = data[i:i + 1]
            if in_str:
                if esc:
                    esc = False
                elif c == b'\\':
                    esc = True
                elif c == b'"':
                    in_str = False
                continue
            if c == b'"':
                in_str = True
            elif c == b'{':
                depth += 1
            elif c == b'}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end:
            snippet = data[start:end]
            try:
                json.loads(snippet)
                blocks.append({'offset': start, 'length': end - start, 'preview': snippet[:120].decode('utf-8', 'replace')})
            except Exception:
                pass
        if len(blocks) >= max_blocks:
            break
    return blocks


# --------------------------------------------------------------------------
# RAW image codec ("RAW\0" magic) — proprietary RGB565 (+ optional 4bpp alpha)
# --------------------------------------------------------------------------
@dataclass
class RawImage:
    width: int
    height: int
    pixel_format_byte: int
    alpha_flag: int
    reserved: int
    rgb_size: int
    rgb_data: bytes
    alpha_data: bytes
    raw_header: bytes

    HEADER_SIZE = 16
    MAGIC = b'RAW\x00'

    @classmethod
    def parse(cls, data: bytes) -> "RawImage":
        if data[:4] != cls.MAGIC:
            raise ValueError(f"Not a RAW image (magic={data[:4]!r})")
        w, h = struct.unpack_from('<HH', data, 4)
        pixfmt = data[8]
        alpha_flag = data[9]
        reserved = struct.unpack_from('<H', data, 10)[0]
        rgb_size_field = struct.unpack_from('<I', data, 12)[0]
        payload = data[16:]
        # Field is 0 for uncompressed/no-alpha images; in that case the RGB
        # plane is simply w*h*2 bytes (RGB565, 2 bytes/pixel).
        rgb_size = rgb_size_field if rgb_size_field else w * h * 2
        rgb_data = payload[:rgb_size]
        alpha_len = (w * h + 1) // 2  # 4 bits/pixel, packed 2 pixels/byte
        alpha_data = payload[rgb_size:rgb_size + alpha_len] if alpha_flag else b''
        return cls(w, h, pixfmt, alpha_flag, reserved, rgb_size, rgb_data, alpha_data, data[:16])

    def to_rgba_bytes(self) -> bytes:
        """Return raw RGBA8888 bytes (row-major), decoding RGB565 + optional
        4-bit alpha nibble mask."""
        out = bytearray(self.width * self.height * 4)
        rgb = self.rgb_data
        alpha = self.alpha_data
        has_alpha = bool(self.alpha_flag)
        n_pixels = self.width * self.height
        for p in range(n_pixels):
            o = p * 2
            if o + 1 >= len(rgb):
                break
            val = (rgb[o] << 8) | rgb[o + 1]  # RGB565, big-endian
            r = (val >> 11) & 0x1F
            g = (val >> 5) & 0x3F
            b = val & 0x1F
            r8 = (r * 255) // 31
            g8 = (g * 255) // 63
            b8 = (b * 255) // 31
            a8 = 255
            if has_alpha:
                byte_idx = p // 2
                if byte_idx < len(alpha):
                    byte = alpha[byte_idx]
                    nib = (byte & 0x0F) if p % 2 == 0 else ((byte >> 4) & 0x0F)
                    a8 = (nib * 255) // 15
            oo = p * 4
            out[oo] = r8
            out[oo + 1] = g8
            out[oo + 2] = b8
            out[oo + 3] = a8
        return bytes(out)

    def summary(self):
        return {
            'width': self.width,
            'height': self.height,
            'pixel_format_byte': hex(self.pixel_format_byte),
            'has_alpha': bool(self.alpha_flag),
            'alpha_flag_byte': hex(self.alpha_flag),
            'rgb_plane_bytes': self.rgb_size,
            'alpha_plane_bytes': len(self.alpha_data),
            'expected_rgb_bytes(w*h*2)': self.width * self.height * 2,
            'expected_alpha_bytes(w*h/2)': (self.width * self.height + 1) // 2,
        }


# --------------------------------------------------------------------------
# IWF container format
# --------------------------------------------------------------------------
@dataclass
class IWFEntry:
    name: str
    offset: int
    size: int
    data: bytes = field(repr=False, default=b'')


@dataclass
class IWFContainer:
    version: int
    entries: list
    raw: bytes

    MAGIC = b'iwf\x00'
    ENTRY_SIZE = 40
    NAME_FIELD_SIZE = 32
    HEADER_SIZE = 8

    @classmethod
    def parse(cls, data: bytes) -> "IWFContainer":
        if data[:4] != cls.MAGIC:
            raise ValueError(f"Not an IWF container (magic={data[:4]!r})")
        version, count = struct.unpack_from('<HH', data, 4)
        entries = []
        off = cls.HEADER_SIZE
        for i in range(count):
            chunk = data[off:off + cls.ENTRY_SIZE]
            if len(chunk) < cls.ENTRY_SIZE:
                break
            name = chunk[:cls.NAME_FIELD_SIZE].split(b'\x00')[0].decode('utf-8', 'replace')
            file_off, file_size = struct.unpack_from('<II', chunk, cls.NAME_FIELD_SIZE)
            entries.append(IWFEntry(name, file_off, file_size, data[file_off:file_off + file_size]))
            off += cls.ENTRY_SIZE
        return cls(version, entries, data)

    def get(self, name: str) -> Optional[IWFEntry]:
        for e in self.entries:
            if e.name == name:
                return e
        return None

    def table_end_offset(self):
        return self.HEADER_SIZE + len(self.entries) * self.ENTRY_SIZE


def load_container_from_path(path: str) -> IWFContainer:
    """Load a watch face file which may be a raw .iwf container OR a .zip
    archive wrapping one (some tooling / newer devices ship .zip)."""
    data = open(path, 'rb').read()
    if data[:4] == IWFContainer.MAGIC:
        return IWFContainer.parse(data)
    if data[:4] == b'PK\x03\x04':
        zf = zipfile.ZipFile(io.BytesIO(data))
        # look for an inner .iwf, or treat the zip members themselves as the
        # asset set (fallback container-less mode handled by caller).
        for name in zf.namelist():
            if name.lower().endswith('.iwf'):
                inner = zf.read(name)
                if inner[:4] == IWFContainer.MAGIC:
                    return IWFContainer.parse(inner)
        raise ValueError("ZIP does not contain a recognized .iwf container")
    raise ValueError(f"Unrecognized file format, magic={data[:4]!r}")


# --------------------------------------------------------------------------
# Structure map + full analysis report
# --------------------------------------------------------------------------
def build_structure_map(container: IWFContainer):
    smap = {
        'magic': container.MAGIC.decode('latin1'),
        'version': container.version,
        'entry_count': len(container.entries),
        'header_size': container.HEADER_SIZE,
        'entry_record_size': container.ENTRY_SIZE,
        'table_end_offset': container.table_end_offset(),
        'entries': [],
    }
    for e in container.entries:
        info = {'name': e.name, 'offset': e.offset, 'size': e.size}
        if e.data[:4] == RawImage.MAGIC:
            try:
                img = RawImage.parse(e.data)
                info['type'] = 'RAW image'
                info['image_info'] = img.summary()
            except Exception as ex:
                info['type'] = 'RAW image (parse error)'
                info['error'] = str(ex)
        elif e.data.strip().startswith(b'{'):
            info['type'] = 'JSON'
            try:
                info['json_preview'] = json.loads(e.data)
            except Exception:
                info['type'] = 'text (JSON-like, failed parse)'
        else:
            info['type'] = 'unknown/binary'
        smap['entries'].append(info)
    return smap


def analyze(path: str) -> str:
    data = open(path, 'rb').read()
    lines = []
    lines.append(f"=== Analysis report for {path} ===")
    lines.append(f"File size: {len(data)} bytes")
    lines.append(f"First 16 bytes: {data[:16].hex()}")
    lines.append("")

    is_iwf = data[:4] == IWFContainer.MAGIC
    is_zip = data[:4] == b'PK\x03\x04'
    lines.append(f"Detected as IWF container: {is_iwf}")
    lines.append(f"Detected as ZIP archive: {is_zip}")
    lines.append("")

    lines.append("--- Signature scan (top-level) ---")
    hits = signature_scan(data)
    by_sig = {}
    for h in hits:
        by_sig.setdefault(h['signature'], []).append(h['offset'])
    for sig, offsets in by_sig.items():
        preview = offsets[:10]
        more = f" (+{len(offsets)-10} more)" if len(offsets) > 10 else ""
        lines.append(f"  {sig}: {len(offsets)} hit(s) at offsets {preview}{more}")
    lines.append("")

    if is_iwf or is_zip:
        try:
            container = load_container_from_path(path)
        except Exception as ex:
            lines.append(f"Container parse failed: {ex}")
            return "\n".join(lines)

        lines.append("--- IWF container structure ---")
        lines.append(f"Magic: {container.MAGIC!r}")
        lines.append(f"Version: {container.version}")
        lines.append(f"Entry count: {len(container.entries)}")
        lines.append(f"Header size: {container.HEADER_SIZE} bytes")
        lines.append(f"Table-of-contents entry size: {container.ENTRY_SIZE} bytes "
                      f"(32-byte null-padded name + u32 LE offset + u32 LE size)")
        lines.append(f"Table ends at offset {container.table_end_offset()} "
                      f"(matches first blob offset: "
                      f"{container.entries[0].offset == container.table_end_offset() if container.entries else 'n/a'})")
        lines.append("")

        lines.append("--- Entries ---")
        for e in container.entries:
            kind = "?"
            extra = ""
            if e.data[:4] == RawImage.MAGIC:
                try:
                    img = RawImage.parse(e.data)
                    kind = "RAW image"
                    extra = (f" [{img.width}x{img.height}, "
                             f"alpha={'yes' if img.alpha_flag else 'no'}, "
                             f"rgb_bytes={img.rgb_size}, alpha_bytes={len(img.alpha_data)}]")
                except Exception as ex:
                    kind = f"RAW image (parse error: {ex})"
            elif e.data.strip().startswith(b'{'):
                kind = "JSON"
            lines.append(f"  {e.name:20s} off={e.offset:>8} size={e.size:>8}  {kind}{extra}")
        lines.append("")

        iwf_json_entry = container.get('iwf.json')
        if iwf_json_entry:
            lines.append("--- iwf.json (layout/metadata) ---")
            try:
                meta = json.loads(iwf_json_entry.data)
                lines.append(json.dumps(meta, indent=2, ensure_ascii=False))
            except Exception as ex:
                lines.append(f"(failed to parse: {ex})")
            lines.append("")

        font_json_entry = container.get('font.json')
        if font_json_entry:
            lines.append("--- font.json ---")
            lines.append(font_json_entry.data.decode('utf-8', 'replace'))
            lines.append("")
    else:
        lines.append("--- Text/JSON block scan ---")
        blocks = find_text_json_blocks(data)
        for b in blocks[:20]:
            lines.append(f"  offset={b['offset']} len={b['length']} preview={b['preview']!r}")
        lines.append("")

    return "\n".join(lines)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    target = sys.argv[1]
    print(analyze(target))
