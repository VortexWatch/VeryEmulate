"""
iwf_format.py — Core format support for VeryEmulate.

This module implements the reverse-engineered `.iwf` container format and
the proprietary `RAW` image codec, as documented in
docs/FORMAT_SPEC.md. It is intentionally defensive: malformed or
unrecognized data should raise a `FormatWarning`-carrying result rather
than an unhandled exception, so the GUI can display diagnostics instead
of crashing.
"""
from __future__ import annotations
import io
import json
import os
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Optional


class FormatIssue(Exception):
    """Non-fatal format issue — carries a human-readable message. Callers
    catch this and display it in the diagnostics panel rather than letting
    it propagate as a crash."""
    pass


# --------------------------------------------------------------------------
# RAW image codec
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
    warnings: list = field(default_factory=list)

    MAGIC = b'RAW\x00'
    HEADER_SIZE = 16

    @classmethod
    def parse(cls, data: bytes) -> "RawImage":
        warnings = []
        if len(data) < cls.HEADER_SIZE:
            raise FormatIssue(f"RAW image blob too short ({len(data)} bytes)")
        if data[:4] != cls.MAGIC:
            raise FormatIssue(f"Bad RAW magic: {data[:4]!r}")
        w, h = struct.unpack_from('<HH', data, 4)
        if w == 0 or h == 0 or w > 4096 or h > 4096:
            raise FormatIssue(f"Implausible RAW image dimensions {w}x{h}")
        pixfmt = data[8]
        alpha_flag = data[9]
        reserved = struct.unpack_from('<H', data, 10)[0]
        if reserved != 0:
            warnings.append(f"reserved field non-zero (0x{reserved:04x})")
        if pixfmt != 0x85:
            warnings.append(f"unexpected pixel_format byte 0x{pixfmt:02x} (expected 0x85/RGB565)")
        rgb_size_field = struct.unpack_from('<I', data, 12)[0]
        payload = data[cls.HEADER_SIZE:]
        rgb_size = rgb_size_field if rgb_size_field else w * h * 2
        if rgb_size > len(payload):
            warnings.append(f"declared rgb_size {rgb_size} exceeds available payload {len(payload)}; clamping")
            rgb_size = len(payload)
        rgb_data = payload[:rgb_size]
        alpha_len = (w * h + 1) // 2
        alpha_data = b''
        if alpha_flag:
            alpha_data = payload[rgb_size:rgb_size + alpha_len]
            if len(alpha_data) < alpha_len:
                warnings.append(f"alpha plane truncated: expected {alpha_len}, got {len(alpha_data)}")
        return cls(w, h, pixfmt, alpha_flag, reserved, rgb_size, rgb_data, alpha_data, warnings)

    def to_rgba_bytes(self) -> bytes:
        """Decode to raw RGBA8888 (row-major). Defensive against truncated
        data — pads with transparent black rather than raising."""
        n_pixels = self.width * self.height
        out = bytearray(n_pixels * 4)
        rgb = self.rgb_data
        alpha = self.alpha_data
        has_alpha = bool(self.alpha_flag)
        rgb_len = len(rgb)
        alpha_len = len(alpha)
        for p in range(n_pixels):
            o = p * 2
            if o + 1 >= rgb_len:
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
                bi = p // 2
                if bi < alpha_len:
                    byte = alpha[bi]
                    nib = (byte & 0x0F) if p % 2 == 0 else ((byte >> 4) & 0x0F)
                    a8 = (nib * 255) // 15
            oo = p * 4
            out[oo] = r8
            out[oo + 1] = g8
            out[oo + 2] = b8
            out[oo + 3] = a8
        return bytes(out)


# --------------------------------------------------------------------------
# IWF container
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
    source_path: str = ""
    warnings: list = field(default_factory=list)

    MAGIC = b'iwf\x00'
    ENTRY_SIZE = 40
    NAME_FIELD_SIZE = 32
    HEADER_SIZE = 8

    @classmethod
    def parse(cls, data: bytes, source_path: str = "") -> "IWFContainer":
        warnings = []
        if data[:4] != cls.MAGIC:
            raise FormatIssue(f"Not an IWF container (magic={data[:4]!r})")
        version, count = struct.unpack_from('<HH', data, 4)
        entries = []
        off = cls.HEADER_SIZE
        for i in range(count):
            chunk = data[off:off + cls.ENTRY_SIZE]
            if len(chunk) < cls.ENTRY_SIZE:
                warnings.append(f"TOC truncated at entry {i}")
                break
            name = chunk[:cls.NAME_FIELD_SIZE].split(b'\x00')[0].decode('utf-8', 'replace')
            file_off, file_size = struct.unpack_from('<II', chunk, cls.NAME_FIELD_SIZE)
            if file_off + file_size > len(data):
                warnings.append(f"entry '{name}' extends past EOF (off={file_off}, size={file_size}, filelen={len(data)}); truncating")
                blob = data[file_off:len(data)]
            else:
                blob = data[file_off:file_off + file_size]
            entries.append(IWFEntry(name, file_off, file_size, blob))
            off += cls.ENTRY_SIZE
        return cls(version, entries, source_path, warnings)

    def get(self, name: str) -> Optional[IWFEntry]:
        for e in self.entries:
            if e.name == name:
                return e
        return None

    def get_layout(self) -> dict:
        e = self.get('iwf.json')
        if not e:
            raise FormatIssue("Container has no iwf.json — cannot determine layout")
        try:
            return json.loads(e.data)
        except Exception as ex:
            raise FormatIssue(f"iwf.json failed to parse: {ex}")

    def get_font_config(self) -> dict:
        e = self.get('font.json')
        if not e:
            return {}
        try:
            return json.loads(e.data)
        except Exception:
            return {}

    def get_image(self, name: str) -> Optional[RawImage]:
        e = self.get(name)
        if not e or not e.data:
            return None
        try:
            return RawImage.parse(e.data)
        except FormatIssue:
            return None


def load_watchface(path: str) -> IWFContainer:
    """Load a .iwf file or a .zip wrapping a .iwf. Raises FormatIssue on
    unrecoverable failure; the caller (GUI) should catch and display."""
    with open(path, 'rb') as f:
        data = f.read()

    if data[:4] == IWFContainer.MAGIC:
        return IWFContainer.parse(data, source_path=path)

    if data[:4] == b'PK\x03\x04':
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except Exception as ex:
            raise FormatIssue(f"File looks like a ZIP but failed to open: {ex}")
        # 1) look for an inner .iwf container
        for name in zf.namelist():
            if name.lower().endswith('.iwf'):
                inner = zf.read(name)
                if inner[:4] == IWFContainer.MAGIC:
                    return IWFContainer.parse(inner, source_path=f"{path}!{name}")
        # 2) fallback: synthesize a pseudo-container from loose zip members
        #    (some tooling ships watch faces as a flat zip of iwf.json +
        #    assets rather than the packed binary container).
        names = zf.namelist()
        if any(n.lower() == 'iwf.json' for n in names):
            entries = []
            for n in names:
                if n.endswith('/'):
                    continue
                blob = zf.read(n)
                entries.append(IWFEntry(name=os.path.basename(n), offset=-1, size=len(blob), data=blob))
            return IWFContainer(version=0, entries=entries, source_path=path,
                                 warnings=["Loaded from loose ZIP members (no packed iwf.json/binary TOC); "
                                           "offsets are synthetic (-1)."])
        raise FormatIssue("ZIP does not contain a recognized watch face (no .iwf member, no iwf.json)")

    raise FormatIssue(f"Unrecognized file format (magic bytes: {data[:8].hex()})")
