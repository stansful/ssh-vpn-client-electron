# Icons

The canonical application icon is `icon.svg` in the repository root.

- `icon.png` is a 256x256 rasterized copy for Linux/AppImage metadata.
- `icon.ico` is a multi-size 32-bit DIB ICO container used by Electron Builder for EXE packaging. Avoid PNG-only ICO output; some Windows shell contexts render it with a white background.
- `icon.icns` is the macOS icon container used by Electron Builder for DMG/ZIP packaging.
- `trayTemplate.png` (16x16, 72 dpi) and `trayTemplate@2x.png` (32x32, 144 dpi) are the black-on-transparent
  macOS menu-bar template icon. macOS applies the correct white/black tint for the current menu-bar appearance.

Run `npm run icons:transparent` after changing `icon.svg` or raster icon assets.
`trayTemplate.svg` (16x16 viewBox) is the source of the tray PNGs. Every packaging build regenerates them once
(`package:prepare` runs `npm run icons:tray`); run it yourself to see a change in `npm run dev`. The script renders both sizes with `scripts/svg-template-raster.mjs` (no browser needed; it accepts a small SVG subset and
treats white paint as an eraser) and refuses ink in the outer pixel ring. Keep the badge corner in mind: connecting,
connected and error states cut a 9 px badge into the bottom-right of the glyph at runtime.
