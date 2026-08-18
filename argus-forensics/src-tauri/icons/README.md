Place application icons here before release builds.

Generate from a 1024×1024 PNG logo:

```powershell
cargo tauri icon path\to\logo.png
```

This creates `icon.ico` and platform variants required by `tauri.conf.json`.
