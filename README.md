# VeryEmulate — VeryFit Watch Face Viewer and Emulator

A Python/PySide6 tool for reverse-engineering, viewing, and emulating
`.iwf` watch face files used by VeryFit/IDW-branded smartwatches (Zephyr
RTOS + Actions Semiconductor zs308a SoC, "DOUI" UI framework).

## Project layout

```
docs/
  FORMAT_SPEC.md            <- Phase 1: full reverse-engineered format spec
  analysis_report_f283.txt  <- Generated analysis of the sample .iwf file
  analysis_report_fw.txt    <- Generated analysis of the OTA firmware image
tools/
  iwf_analyzer.py           <- Phase 1: standalone parser/scanner/report CLI
veryemulate/
  main.py                   <- Phase 2: PySide6 application entry point
  iwf_format.py             <- Container + RAW image codec (core parser)
  renderer.py                <- QGraphicsScene-based watch face renderer
  hexview.py                 <- Hex viewer widget
```

Features:
- Loads `.iwf` containers and `.zip`-wrapped `.iwf` files
- Renders immediately using the current system time (analog hands +
  digital date/weekday widgets), updates live
- **Assets** tab: browse every embedded asset with a live preview
- **Hex Viewer** tab: raw hex/ASCII dump of the loaded file
- **Structure Map** tab: parsed container table-of-contents
- **Diagnostics** tab: warnings for any unrecognized/corrupt structure —
  the app is built to degrade gracefully (placeholders + warnings) rather
  than crash on unknown widget types or malformed data
