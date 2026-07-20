#!/usr/bin/env python3
"""
VeryEmulate — VeryFit Watch Face Viewer and Emulator

Loads .iwf (and .zip-wrapped .iwf) watch face files, renders them using the
current system time, and provides diagnostics tooling (asset browser, hex
viewer, structure map, warning log) built on top of the reverse-engineered
format described in docs/FORMAT_SPEC.md.

Run:
    python3 main.py [optional/path/to/file.iwf]
"""
from __future__ import annotations
import sys
import os
import json
import traceback

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QPixmap, QIcon
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTabWidget, QFileDialog, QLabel, QListWidget, QListWidgetItem,
    QPlainTextEdit, QMessageBox, QToolBar, QStatusBar, QSizePolicy,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from iwf_format import load_watchface, IWFContainer, RawImage, FormatIssue
from renderer import WatchFaceView, raw_image_to_qimage
from hexview import HexView, format_hex_dump


class AssetBrowser(QWidget):
    """List of all entries in the loaded container with a preview pane."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        self.list_widget = QListWidget()
        self.list_widget.setMaximumWidth(260)
        self.list_widget.currentItemChanged.connect(self._on_select)
        layout.addWidget(self.list_widget)

        right = QVBoxLayout()
        self.preview_label = QLabel("Select an asset to preview")
        self.preview_label.setAlignment(Qt.AlignCenter)
        self.preview_label.setMinimumHeight(220)
        self.preview_label.setStyleSheet("background:#1e1e1e; color:#aaa; border:1px solid #444;")
        right.addWidget(self.preview_label)
        self.info_box = QPlainTextEdit()
        self.info_box.setReadOnly(True)
        self.info_box.setMaximumHeight(160)
        right.addWidget(self.info_box)
        right_widget = QWidget()
        right_widget.setLayout(right)
        layout.addWidget(right_widget)

        self.container = None

    def load(self, container: IWFContainer):
        self.container = container
        self.list_widget.clear()
        for e in container.entries:
            label = f"{e.name}   ({e.size} bytes)"
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, e.name)
            self.list_widget.addItem(item)
        if container.entries:
            self.list_widget.setCurrentRow(0)

    def _on_select(self, current, previous):
        if not current or not self.container:
            return
        name = current.data(Qt.UserRole)
        entry = self.container.get(name)
        if not entry:
            return
        info_lines = [f"name: {entry.name}", f"offset: {entry.offset}", f"size: {entry.size} bytes"]
        if entry.data[:4] == RawImage.MAGIC:
            try:
                img = RawImage.parse(entry.data)
                info_lines.append(f"type: RAW image {img.width}x{img.height}")
                info_lines.append(f"alpha: {'yes' if img.alpha_flag else 'no'}")
                if img.warnings:
                    info_lines.append("warnings: " + "; ".join(img.warnings))
                qimg = raw_image_to_qimage(img)
                pm = QPixmap.fromImage(qimg)
                scaled = pm.scaled(220, 220, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.preview_label.setPixmap(scaled)
                self.preview_label.setText("")
            except FormatIssue as ex:
                self.preview_label.setText(f"Decode failed:\n{ex}")
                info_lines.append(f"decode error: {ex}")
        elif entry.data.strip()[:1] == b'{':
            self.preview_label.setPixmap(QPixmap())
            try:
                parsed = json.loads(entry.data)
                self.preview_label.setText(json.dumps(parsed, indent=2, ensure_ascii=False)[:2000])
            except Exception:
                self.preview_label.setText(entry.data[:2000].decode('utf-8', 'replace'))
            info_lines.append("type: JSON")
        else:
            self.preview_label.setPixmap(QPixmap())
            self.preview_label.setText("(binary — see Hex Viewer tab)")
            info_lines.append("type: unknown/binary")
        self.info_box.setPlainText("\n".join(info_lines))


class DiagnosticsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        layout.addWidget(QLabel("Warnings & diagnostics (unknown structures never crash the app — they're logged here):"))
        layout.addWidget(self.text)

    def set_messages(self, messages):
        if not messages:
            self.text.setPlainText("No warnings — container parsed cleanly.")
        else:
            self.text.setPlainText("\n".join(f"⚠ {m}" for m in messages))

    def append(self, msg: str):
        self.text.appendPlainText(f"⚠ {msg}")


class StructureMapPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        f = self.text.font()
        f.setFamily("Courier New")
        self.text.setFont(f)
        layout.addWidget(self.text)

    def load(self, container: IWFContainer):
        lines = []
        lines.append(f"magic: {container.MAGIC!r}")
        lines.append(f"version: {container.version}")
        lines.append(f"entry_count: {len(container.entries)}")
        lines.append(f"header_size: {container.HEADER_SIZE}")
        lines.append(f"entry_record_size: {container.ENTRY_SIZE}")
        lines.append("")
        lines.append(f"{'name':22s} {'offset':>10s} {'size':>10s}  type")
        lines.append("-" * 70)
        for e in container.entries:
            kind = "?"
            if e.data[:4] == RawImage.MAGIC:
                try:
                    img = RawImage.parse(e.data)
                    kind = f"RAW image {img.width}x{img.height} alpha={'y' if img.alpha_flag else 'n'}"
                except FormatIssue:
                    kind = "RAW image (parse error)"
            elif e.data.strip()[:1] == b'{':
                kind = "JSON"
            lines.append(f"{e.name:22s} {e.offset:>10} {e.size:>10}  {kind}")
        self.text.setPlainText("\n".join(lines))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VeryEmulate — VeryFit Watch Face Viewer and Emulator")
        self.resize(1100, 720)
        self.setAcceptDrops(True)

        self.container = None

        # -- toolbar --
        toolbar = QToolBar("Main")
        self.addToolBar(toolbar)
        open_action = QAction("Open Watch Face…", self)
        open_action.triggered.connect(self.open_file_dialog)
        toolbar.addAction(open_action)

        # -- central tabs --
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.view = WatchFaceView()
        self.tabs.addTab(self.view, "Render")

        self.asset_browser = AssetBrowser()
        self.tabs.addTab(self.asset_browser, "Assets")

        self.hex_view = HexView()
        self.tabs.addTab(self.hex_view, "Hex Viewer")

        self.structure_panel = StructureMapPanel()
        self.tabs.addTab(self.structure_panel, "Structure Map")

        self.diagnostics = DiagnosticsPanel()
        self.tabs.addTab(self.diagnostics, "Diagnostics")

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("No watch face loaded. Use File > Open, or drag & drop a .iwf/.zip file.")

    # -- file loading ---------------------------------------------------
    def open_file_dialog(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open watch face", "", "Watch faces (*.iwf *.zip);;All files (*)")
        if path:
            self.load_path(path)

    def load_path(self, path: str):
        try:
            container = load_watchface(path)
        except FormatIssue as ex:
            QMessageBox.warning(self, "Failed to load", str(ex))
            self.status.showMessage(f"Failed to load {path}: {ex}")
            return
        except Exception as ex:
            # Absolute last resort — never let an unknown structure crash
            # the whole app. Show full traceback in Diagnostics instead.
            tb = traceback.format_exc()
            QMessageBox.critical(self, "Unexpected error",
                                  f"An unexpected error occurred while loading this file.\n"
                                  f"See the Diagnostics tab for details.")
            self.diagnostics.append(f"Unexpected error loading {path}:\n{tb}")
            self.tabs.setCurrentWidget(self.diagnostics)
            return

        self.container = container
        try:
            self.view.load_container(container)
        except Exception as ex:
            tb = traceback.format_exc()
            self.diagnostics.append(f"Render error: {ex}\n{tb}")

        self.asset_browser.load(container)
        self.structure_panel.load(container)

        with open(path, 'rb') as f:
            raw = f.read()
        self.hex_view.show_bytes(raw, title=f"{os.path.basename(path)} ({len(raw)} bytes)")

        all_warnings = list(container.warnings) + self.view.current_warnings()
        self.diagnostics.set_messages(all_warnings)

        self.setWindowTitle(f"VeryEmulate — {os.path.basename(path)}")
        self.status.showMessage(
            f"Loaded {os.path.basename(path)}  |  {len(container.entries)} assets  |  "
            f"{len(all_warnings)} diagnostic warning(s)")

    # -- drag & drop ------------------------------------------------------
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if path:
                self.load_path(path)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("VeryEmulate")
    win = MainWindow()
    win.show()
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        win.load_path(sys.argv[1])
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
