# Sample Payloads & Reference Binaries

This folder contains reverse-engineered sample payloads and reference files extracted from Advanced Installer SFX setups (e.g. OceanofGames installers):

```
samples/
└── payloads/
    ├── Step 3 - Setup_Install_Game.ini   (Installer configuration and GUID manifest)
    ├── original_installer_decoder.dll    (Original 32-bit vendor decoder extracted from installer)
    └── 326FA02/
        ├── FILES.7z                      (Primary application payload, 5.2 MB)
        └── OceanofGames-Top-Games-EXE.7z (Secondary installer payload, 635 KB)
```

## Details:
- **`original_installer_decoder.dll`**: The original 32-bit decoder shipped by the installer vendor. Used for reverse engineering the exported functions and verifying ABI compatibility.
- **`Step 3 - Setup_Install_Game.ini`**: Extracted MSI/SFX configuration file specifying product GUIDs, silent arguments, and installation folders.
- **`326FA02/*.7z`**: Extracted 7z archives with headers de-obfuscated via `standalone_extractor.exe`.
