"""
renderer.py — Turns a parsed IWFContainer + iwf.json layout into an on-screen
rendering, using PySide6's QGraphicsScene. Analog hands are rotated around
their documented pivot/anchor points; digital widgets are composed from
individual glyph-strip assets. Anything unrecognized degrades to a visible
placeholder rather than crashing.
"""
from __future__ import annotations
import datetime
from PySide6.QtCore import Qt, QTimer, QRectF
from PySide6.QtGui import QImage, QPixmap, QPainter, QColor, QPen, QFont
from PySide6.QtWidgets import (QGraphicsScene, QGraphicsView, QGraphicsPixmapItem,
                                QGraphicsRectItem, QGraphicsSimpleTextItem)

from iwf_format import IWFContainer, RawImage, FormatIssue

# Day-of-week asset suffixes observed in the sample (note the non-standard
# 4-letter "thur" — this was verified against the actual asset names in
# f283.iwf, not assumed from a standard abbreviation table).
WEEKDAY_SUFFIXES = ['mon', 'tue', 'wed', 'thur', 'fri', 'sat', 'sun']  # Mon=0 .. Sun=6


def raw_image_to_qimage(img: RawImage) -> QImage:
    rgba = img.to_rgba_bytes()
    qimg = QImage(bytes(rgba), img.width, img.height, img.width * 4, QImage.Format_RGBA8888)
    # QImage does not own the buffer by reference in all Qt bindings the same
    # way; force a deep copy so it's safe to use after `rgba` goes out of scope.
    return qimg.copy()


class AssetCache:
    """Decodes and caches RawImage -> QPixmap conversions for a container."""

    def __init__(self, container: IWFContainer):
        self.container = container
        self._cache = {}
        self.warnings = []

    def get_pixmap(self, name: str):
        if name in self._cache:
            return self._cache[name]
        entry = self.container.get(name)
        if entry is None:
            self.warnings.append(f"Asset '{name}' referenced by layout but not found in container")
            self._cache[name] = None
            return None
        try:
            img = RawImage.parse(entry.data)
            if img.warnings:
                for w in img.warnings:
                    self.warnings.append(f"Asset '{name}': {w}")
            qimg = raw_image_to_qimage(img)
            pm = QPixmap.fromImage(qimg)
            self._cache[name] = pm
        except FormatIssue as ex:
            self.warnings.append(f"Asset '{name}' failed to decode: {ex}")
            self._cache[name] = None
        except Exception as ex:
            self.warnings.append(f"Asset '{name}' unexpected decode error: {ex}")
            self._cache[name] = None
        return self._cache[name]


def _placeholder_item(w, h, label):
    rect = QGraphicsRectItem(0, 0, max(w, 20), max(h, 14))
    rect.setPen(QPen(QColor(255, 0, 0)))
    rect.setBrush(QColor(60, 0, 0, 120))
    text = QGraphicsSimpleTextItem(label, rect)
    text.setBrush(QColor(255, 200, 200))
    f = QFont()
    f.setPointSize(7)
    text.setFont(f)
    return rect


class WatchFaceScene(QGraphicsScene):
    """A QGraphicsScene that lays out one parsed watch face and refreshes
    time-dependent widgets on a timer."""

    def __init__(self, container: IWFContainer, parent=None):
        super().__init__(parent)
        self.container = container
        self.assets = AssetCache(container)
        self.warnings = []
        self.layout = {}
        self.canvas_w = 240
        self.canvas_h = 284
        self._hand_items = {}   # widget item dict -> (QGraphicsPixmapItem, cx, cy, ax, ay, kind)
        self._digital_items = []  # list of (item_spec, group placeholder) for periodic refresh

        try:
            self.layout = container.get_layout()
        except FormatIssue as ex:
            self.warnings.append(str(ex))
            self.layout = {}

        self._build()

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_time)
        self.timer.start(200)  # 5x/sec is plenty smooth without busy-looping
        self.refresh_time()

    # -- construction -----------------------------------------------------
    def _build(self):
        w = self.layout.get('w') or 240
        h = self.layout.get('h') or 284
        # Prefer background image's own resolution if present — matches the
        # documented "native display resolution" convention (§3.1 of spec).
        bg_name = self.layout.get('bkground')
        if bg_name:
            pm = self.assets.get_pixmap(bg_name)
            if pm:
                w, h = pm.width(), pm.height()
        self.canvas_w, self.canvas_h = w, h
        self.setSceneRect(0, 0, w, h)

        # base background
        if bg_name:
            pm = self.assets.get_pixmap(bg_name)
            if pm:
                bg_item = QGraphicsPixmapItem(pm)
                self.addItem(bg_item)
            else:
                self.addItem(_placeholder_item(w, h, f"missing bg: {bg_name}"))
        else:
            self.addItem(_placeholder_item(w, h, "no background declared"))

        for item_spec in self.layout.get('item', []):
            self._build_item(item_spec)

        for w_ in self.warnings:
            pass  # surfaced via get_warnings(); nothing to draw here

        self.warnings.extend(self.assets.warnings)

    def _build_item(self, spec: dict):
        widget = spec.get('widget')
        kind = spec.get('type')
        try:
            if widget == 'watch' and kind == 'time':
                self._build_analog(spec)
            elif widget == 'custom' and kind in ('date', 'week'):
                self._build_digital(spec)
            else:
                x, y, w, h = spec.get('x', 0), spec.get('y', 0), spec.get('w', 40), spec.get('h', 20)
                ph = _placeholder_item(w, h, f"unsupported: {widget}/{kind}")
                ph.setPos(x, y)
                self.addItem(ph)
                self.warnings.append(f"Unsupported widget type '{widget}/{kind}' — rendered as placeholder "
                                      f"(no confirmed field layout in FORMAT_SPEC.md yet)")
        except Exception as ex:
            self.warnings.append(f"Failed to build widget {widget}/{kind}: {ex}")

    def _build_analog(self, spec: dict):
        for hand in ('hour', 'minute', 'second'):
            asset_name = spec.get(hand)
            if not asset_name:
                continue
            pm = self.assets.get_pixmap(asset_name)
            cx = spec.get(f'{hand[:3] if hand!="minute" else "min"}centerx',
                           spec.get(f'{hand}centerx', 0))
            # iwf.json uses irregular prefixes: seccenterx/secanchorx, mincenterx/minanchorx,
            # hourcenterx/houranchorx — handle exactly as observed.
            prefix = {'hour': 'hour', 'minute': 'min', 'second': 'sec'}[hand]
            cx = spec.get(f'{prefix}centerx', 0)
            cy = spec.get(f'{prefix}centery', 0)
            ax = spec.get(f'{prefix}anchorx', self.canvas_w // 2)
            ay = spec.get(f'{prefix}anchory', self.canvas_h // 2)
            if pm is None:
                ph = _placeholder_item(10, 60, f"missing {hand}: {asset_name}")
                ph.setPos(ax - 5, ay - 30)
                self.addItem(ph)
                continue
            item = QGraphicsPixmapItem(pm)
            item.setTransformOriginPoint(cx, cy)
            item.setPos(ax - cx, ay - cy)
            item.setZValue(10)
            self.addItem(item)
            self._hand_items[hand] = item

    def _build_digital(self, spec: dict):
        # Store the spec; actual glyph composition happens in refresh_time()
        # since it's time-dependent. We add a container group lazily there.
        self._digital_items.append({'spec': spec, 'items': []})

    # -- per-tick refresh ---------------------------------------------------
    def refresh_time(self):
        now = datetime.datetime.now()
        sec = now.second
        minute = now.minute
        hour = now.hour % 12

        if 'second' in self._hand_items:
            self._hand_items['second'].setRotation(sec / 60.0 * 360.0)
        if 'minute' in self._hand_items:
            self._hand_items['minute'].setRotation((minute + sec / 60.0) / 60.0 * 360.0)
        if 'hour' in self._hand_items:
            self._hand_items['hour'].setRotation((hour + minute / 60.0) / 12.0 * 360.0)

        for entry in self._digital_items:
            for old in entry['items']:
                self.removeItem(old)
            entry['items'] = []
            spec = entry['spec']
            kind = spec.get('type')
            font_name = spec.get('font', '')
            x, y = spec.get('x', 0), spec.get('y', 0)
            cursor_x = x
            pixmaps = []
            if kind == 'date':
                text = f"{now.day:02d}"
                for ch in text:
                    name = f"{font_name}_{ch}"
                    pm = self.assets.get_pixmap(name)
                    pixmaps.append((name, pm))
            elif kind == 'week':
                suffix = WEEKDAY_SUFFIXES[now.weekday()]
                name = f"{font_name}_en_{suffix}"
                pm = self.assets.get_pixmap(name)
                pixmaps.append((name, pm))
            for name, pm in pixmaps:
                if pm is None:
                    ph = _placeholder_item(14, 14, "?")
                    ph.setPos(cursor_x, y)
                    self.addItem(ph)
                    entry['items'].append(ph)
                    cursor_x += 14
                    continue
                item = QGraphicsPixmapItem(pm)
                item.setPos(cursor_x, y)
                item.setZValue(5)
                self.addItem(item)
                entry['items'].append(item)
                cursor_x += pm.width()

    def get_warnings(self):
        return list(self.warnings)


class WatchFaceView(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setRenderHint(QPainter.Antialiasing)
        self.setRenderHint(QPainter.SmoothPixmapTransform)
        self.setBackgroundBrush(QColor(20, 20, 20))
        self.setFrameShape(QGraphicsView.NoFrame)
        self._scene_obj = None

    def load_container(self, container: IWFContainer):
        self._scene_obj = WatchFaceScene(container)
        self.setScene(self._scene_obj)
        self.fitInView(self._scene_obj.sceneRect(), Qt.KeepAspectRatio)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._scene_obj is not None:
            self.fitInView(self._scene_obj.sceneRect(), Qt.KeepAspectRatio)

    def current_warnings(self):
        if self._scene_obj:
            return self._scene_obj.get_warnings()
        return []
