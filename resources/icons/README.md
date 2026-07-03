# Icons

The canonical application icon is `icon.svg` in the repository root.

- `icon.png` is a 256x256 rasterized copy for Linux/AppImage metadata.
- `icon.ico` is a multi-size 32-bit DIB ICO container used by Electron Builder for EXE packaging. Avoid PNG-only ICO output; some Windows shell contexts render it with a white background.
- `icon.icns` is the macOS icon container used by Electron Builder for DMG/ZIP packaging.

Run `npm run icons:transparent` after changing `icon.svg` or raster icon assets.
