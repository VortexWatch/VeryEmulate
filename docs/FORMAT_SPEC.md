# VeryFit / IDW `.iwf` Watch Face Format — Reverse-Engineering Specification

Derived from binary analysis of `f283.iwf` (246,758 bytes) and cross-referenced
against strings/function names recovered from
`idw26_ota_V1_00_14_20260211.fw` (Zephyr RTOS firmware for the Actions
Semiconductor **zs308a** SoC, running Actions' in-house **DOUI** UI
framework). All offsets and byte values below were verified empirically
against the sample file, not assumed.

---

## 1. Container classification

`.iwf` is **not** a ZIP, TAR, or any standard archive. It is a flat,
proprietary **binary container**: a fixed-size header, a fixed-stride
table-of-contents (TOC), followed by a flat concatenation of raw asset
blobs referenced by absolute offset. This matches the firmware's own
`parse_iwf`, `watch_face_rw_open`, and `"iwf magic errror"` string literals
found in `watch_face_rw_simple.c` — i.e. this is exactly the format the
watch itself parses, not a repackaged intermediate format.

Note: The toolkit also supports (and the device firmware strings suggest
some tooling ships) a **`.zip`-wrapped `.iwf`** variant, where a `.zip`
contains a single `.iwf` member. Both are handled transparently.

---

## 2. Container header (offset 0x00)

| Offset | Size | Field         | Notes |
|--------|------|---------------|-------|
| 0x00   | 4    | `magic`       | ASCII `"iwf\0"` (`69 77 66 00`) |
| 0x04   | 2    | `version`     | u16 LE. Observed value: `1` |
| 0x06   | 2    | `entry_count` | u16 LE. Observed value: `25` (0x19) |

Total header size: **8 bytes**.

---

## 3. Table of contents (starts at offset 0x08)

Immediately follows the header: `entry_count` fixed-size records, **40
bytes each**, no padding between records.

| Offset (rel.) | Size | Field    | Notes |
|----------------|------|----------|-------|
| 0x00 | 32 | `name` | ASCII, NUL-padded/terminated. Not necessarily NUL-terminated with a trailing NUL run to 32 bytes if the name is short, but always fits in 32 bytes. |
| 0x20 | 4  | `offset` | u32 LE — **absolute offset from start of file** to the asset blob |
| 0x24 | 4  | `size`   | u32 LE — byte length of the asset blob |

Table size = `8 + entry_count * 40`. In the sample file this is
`8 + 25*40 = 1008` (`0x3F0`), and the **first entry's offset field is
exactly 1008** — i.e. asset data begins immediately after the TOC with no
gap or alignment padding. This was verified programmatically
(`table_end_offset == entries[0].offset`).

Entries are **not sorted by offset** in file-position order necessarily,
but in this sample they are monotonically increasing.

### 3.1 Observed entries (f283.iwf)

```
iwf.json        off=1008     size=944     JSON  (layout/metadata)
font.json       off=1952     size=90      JSON  (font/glyph-set declarations)
h.png           off=2042     size=8601    RAW image 34x101   (hour hand)
preview.png     off=10643    size=68224   RAW image 174x196  (thumbnail)
m.png           off=78867    size=10176   RAW image 32x127   (minute hand)
ss.png          off=89043    size=8981    RAW image 22x163   (second hand)
files27.png     off=98024    size=136336  RAW image 240x284  (background)
g282_0..g282_10 off=234360.. size=~366ea  RAW image 10x14ish (digit glyph strip "g282")
week_en_*       off=238316.. size=1206ea  RAW image 34x14    (day-of-week glyphs)
```

Despite the `.png` naming convention used for entry names (kept for
human/tooling familiarity), **none of these blobs are real PNG files** —
they all use the proprietary `RAW` codec described below. There is no PNG,
JPEG, or ZIP signature anywhere inside the container; the codec is fully
custom.

---

## 4. `RAW` image codec (per-asset blob format)

Every image-bearing asset blob begins with a 16-byte header:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0x00 | 4 | `magic` | ASCII `"RAW\0"` |
| 0x04 | 2 | `width`  | u16 LE, pixels |
| 0x06 | 2 | `height` | u16 LE, pixels |
| 0x08 | 1 | `pixel_format` | Observed constant `0x85` across all samples (likely encodes "RGB565" internally to the DOUI pixel-format enum; no other value observed) |
| 0x09 | 1 | `alpha_flag` | `0x66` = image has an appended 4bpp alpha mask; `0x00` = fully opaque, no mask |
| 0x0A | 2 | `reserved`   | Observed constant `0x0000` |
| 0x0C | 4 | `rgb_plane_size` | u32 LE. When non-zero: exact byte length of the RGB565 pixel plane that follows. **When zero** (observed only on opaque images with `alpha_flag=0`), the RGB plane size must be computed as `width*height*2` — the field is simply unused/omitted for the no-alpha case. |

### 4.1 Pixel data layout (after the 16-byte header)

1. **RGB565 plane** — `rgb_plane_size` bytes (or `width*height*2` if the
   field was zero). Row-major, top-to-bottom, left-to-right. Each pixel is
   2 bytes, **big-endian** `u16` (`v = (byte0<<8) | byte1` — note this
   differs from the container header/TOC fields, which are little-endian;
   the pixel plane itself is big-endian, consistent with common embedded
   display controller (SPI LCD) conventions), standard 5-6-5 bit packing:
   `R = (v>>11)&0x1F`, `G = (v>>5)&0x3F`, `B = v&0x1F`.
2. **Alpha plane** (only present when `alpha_flag != 0`) — immediately
   follows the RGB plane. **4 bits per pixel**, two pixels packed per byte,
   **low nibble = first (even-indexed) pixel, high nibble = second
   (odd-indexed) pixel**. Length = `ceil(width*height/2)` bytes. Alpha
   value is scaled from a 4-bit (0–15) value to 8-bit via `(nibble*255)//15`.

This was verified by exact byte-accounting across every asset in the
sample (7 independent images, both with and without alpha), e.g.:

```
h.png:      w=34  h=101  rgb=6868   (34*101*2)   alpha=1717 (34*101/2, rounded)  total=8585 == entry_size-16 ✓
files27.png: w=240 h=284  rgb=136320 (240*284*2)  alpha=0 (no-alpha)              total=136320 == entry_size-16 ✓
```

...and confirmed **visually**: decoding `preview.png` and `files27.png`
through this codec and rendering as standard RGBA produces a coherent,
correctly-proportioned watch face image (no corruption, no channel swap,
no stride error).

### 4.2 Relationship to "LZ4"/"FASTLZ" mentioned in metadata/firmware

`iwf.json` in this sample declares `"compress":"LZ4"`, and the firmware
binary contains a FASTLZ decompressor
(`module/compression/fastlz/fastlz_decompress_buff.c`). **However, the
image assets in this particular file are stored uncompressed** (raw
RGB565 + raw 4bpp alpha, no entropy coding) — decompression attempts using
both LZ4 block/frame format and a from-scratch FastLZ level-1 decoder did
**not** produce valid output, whereas the direct byte-for-byte RGB565+alpha
interpretation matched exactly and rendered correctly. Our reading: the
`compress` field and FASTLZ code path are used elsewhere in the
watch-face pipeline (e.g. compressing whole `.iwf` blobs during OTA
transfer, or compressing *other* asset types such as animation sequences
or larger sprite sheets), but are not universally applied to every RAW
image entry. The emulator/parser therefore **auto-detects**: it tries
direct RAW decode first (validated via exact size accounting) and will
fall back to FASTLZ decompression only if the direct byte accounting
doesn't reconcile (implemented as a hook point in the codec, `try_fastlz`,
for forward-compatibility with files that do use it).

---

## 5. Layout / metadata format (`iwf.json`)

Standard JSON (not a custom binary structure). Top-level keys observed:

| Key | Type | Meaning |
|-----|------|---------|
| `version` | int | iwf.json schema version |
| `clouddialversion` | int | cloud-dial-designer schema/tooling version |
| `preview` | string | filename (within container) of the thumbnail |
| `name` | string | watch face short name |
| `author` | string | UTF-8 author name |
| `description` | string | free text (device model, in this sample "IDW13") |
| `deviceId` | string | target device/screen profile identifier |
| `bluetooth`, `disturb`, `battery` | bool | feature toggles (probably: show BT icon / DND icon / battery icon complications — not used in this face) |
| `compress` | string | compression scheme hint (`"LZ4"` observed) — see §4.2 caveat |
| `environment` | string | `"Production"` observed — build/tooling provenance tag |
| `bkground` | string | filename of the full-screen background image |
| `item` | array | ordered list of **widgets** composing the face (see below) |

### 5.1 Widget items (`item[]`)

Each item has a `"widget"` type (`"custom"` or `"watch"` observed) and a
`"type"` sub-kind. This vocabulary matches loader function names found
directly in the firmware (`watch_face_clock_load`, `watch_face_customtext_load`,
`watch_face_ring_load`, `watch_face_histogram_load`,
`watch_face_multimeter_load`, `watch_face_progressbar_load`,
`watch_face_gradient_load`, `watch_face_customanima_load`,
`watch_face_world_time_load`, `watch_face_weather_load`, etc.) — i.e.
`iwf.json`'s `widget`/`type` pair select which DOUI widget loader parses
that item.

**Digital/text widget** (`widget:"custom"`, e.g. `type:"date"`, `type:"week"`):

| Field | Meaning |
|-------|---------|
| `x`,`y`,`w`,`h` | bounding box in screen pixels |
| `fgcolor`, `fgrender` | ARGB hex color (`0xAARRGGBB`) |
| `align` | text alignment (`"left"` observed) |
| `style` | integer render-style selector |
| `font` | name of the glyph-set (matches `font.json` `item[].name`, and the asset name prefix, e.g. `"g282"` → assets `g282_0..g282_10`) |
| `fontnum` | glyph count in the set actually used by this widget |

**Analog watch-hands widget** (`widget:"watch"`, `type:"time"`):

| Field | Meaning |
|-------|---------|
| `x`,`y`,`w`,`h` | usually the full screen (0,0,240,284) |
| `stepless_rotation` | 0/1 — whether hands rotate in fine (stepless) angle increments vs. snapping to fixed positions |
| `second`/`minute`/`hour` | asset filename for each hand's sprite |
| `{hand}centerx`/`{hand}centery` | the **pivot point within the hand sprite itself** — i.e. which pixel of the hand image sits on the rotation axis |
| `{hand}anchorx`/`{hand}anchory` | the **screen position** where that pivot point is placed (typically the watch face's visual center) |

Rendering model: for a given hand, rotate the sprite image about its
internal pivot `(centerx, centery)` by an angle derived from the current
time (`seconds/minutes/hours`), then draw it such that the pivot point
lands at screen position `(anchorx, anchory)`. All three hands in the
sample share the same anchor `(120, 142)` — the visual center of the
240×284 canvas — while each hand has its own internal pivot depending on
where its sprite was authored.

### 5.2 `font.json`

```json
{"item":[{"name":"g282","bpp":16,"format":"png"},
         {"name":"week","bpp":16,"format":"png"}]}
```

Declares each glyph-set used by `custom` widgets: a `name` (matched against
`item[].font` in `iwf.json` and against the asset filename prefix), a
`bpp` (bits-per-pixel color depth — 16 = RGB565, consistent with the RAW
codec), and `format` (`"png"` is a labeling convention only, per §3.1 —
actual bytes are `RAW`-coded).

Glyph assets are **individual pre-rendered bitmap strips**, one file per
character/value (`g282_0`…`g282_10` for digits/punctuation used in dates;
`week_en_mon`…`week_en_sun` for day names) — not a packed font atlas.
This is a bitmap-font-per-glyph scheme, simpler than a traditional font
table.

---

## 6. Animation definitions

No dedicated animation-sequence asset (e.g. frame-timing table, GIF-like
structure) is present in this particular sample. The firmware does expose
a `watch_face_customanima_load` loader and a `douip_animation.c` module,
so animated widgets are a supported *widget type* in the framework, but
this specific face only uses static widgets (`custom`/date, `custom`/week,
`watch`/time). The parser and emulator are built to tolerate/skip
unrecognized widget types gracefully (see §8) so that animation-bearing
faces don't crash the tool — they'll simply render as an unsupported
placeholder until a sample with that widget type is available to
reverse-engineer further.

---

## 7. Firmware cross-reference (`idw26_ota_V1_00_14_20260211.fw`)

Confirms (via `strings` + signature scan, not full disassembly — this was
previously reverse-engineered in depth in earlier sessions):

- Zephyr RTOS (`*** Booting Zephyr OS version %s %s ***`), Actions
  Semiconductor **zs308a** port tree (`port/zs308a/zephyr/...`).
- In-house **DOUI** UI framework (`App/doui/core/*.c`,
  `App/doui/widget/douip_*.c`) — `douip_watch.c` handles the analog clock
  widget, matching the `watch`/`time` item type in `iwf.json`.
- `App/cloud_dial/watch_dail/watch_face_rw_simple.c` contains the literal
  strings `"iwf\0magic errror"` (sic — typo present in firmware) and
  `parse_iwf`, `.iwf`, `watch_face_rw_write_open` — i.e. this file is
  parsed **directly by the firmware itself**, confirming our container
  format understanding matches the on-device parser rather than being an
  intermediate authoring format.
- `App/protocol_v3/protocol_v3_watch_face.c` and BLE queue handles
  (`protocol_v3_queue_get_watch_face_list_handle`, etc.) implement the
  over-BLE watch-face delivery protocol.
- `module/compression/fastlz/fastlz_decompress_buff.c` — confirms FASTLZ
  is present firmware-side (see §4.2 caveat about when it's actually used
  for a given asset).
- Container magic bytes `iwf\0` occur 3 times as **raw literal data**
  inside the firmware image at offsets `0x77778e` (near `parse_iwf`
  strings), `0x105c40` (near `"iwf\0magic errror"`), and `0x18a7fd` (near
  `.iwf` extension handling) — i.e. these are the compiled string
  constants used by the parser, not stray/incidental byte matches.
- No embedded watch-face containers (no `iwf\0` **container instances**,
  only the 3 string literals above) or ZIP archives were found inside the
  firmware image itself — OTA firmware does not appear to bundle
  factory-default watch faces in this build.

---

## 8. Robustness / unknowns for the emulator

The following are explicitly **unknown or unverified** and the emulator
must degrade gracefully rather than crash when it encounters them:

- Other `widget`/`type` combinations beyond `custom`/`date`,
  `custom`/`week`, `watch`/`time` (e.g. `ring`, `histogram`,
  `progressbar`, `linechart`, `gradient`, `multimeter`, `worldtime`,
  `weather`, animated widgets) — loader names exist in firmware, but no
  sample `iwf.json` items of these kinds were available to confirm their
  field layouts.
- The exact semantics of `pixel_format_byte=0x85` beyond "RGB565" (whether
  other pixel formats exist and use a different byte value).
- Whether `rgb_plane_size==0` is a hard rule for "no compression" or
  merely happened to be zero in these samples; the parser treats a zero
  field as "derive from width*height*2" but does not assume this implies
  anything about a compression flag beyond that.
- The precise conditions under which FASTLZ/LZ4 compression is applied to
  an individual asset (see §4.2) — not encountered in this sample set.
