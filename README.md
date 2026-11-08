# YogurtSQL

A fast, secure desktop client for MySQL and MariaDB, free to use. It has a familiar workspace layout, light and dark themes, encrypted credentials, and modern SSH and TLS.

This repository holds the installers and the update feed. The application's source code isn't public.

## Download

Get the latest version from **[Releases](https://github.com/SaqibZafar/yogurtsql-releases/releases/latest)**:

| System | File |
| --- | --- |
| Windows 10 and 11 | `YogurtSQL_<version>_x64-setup.exe` (or the `.msi`) |
| macOS 11 and later (Apple silicon and Intel) | `YogurtSQL_<version>_universal.dmg` |
| Linux | `.AppImage`, `.deb` or `.rpm` |

The other files (`.sig`, `.app.tar.gz` and `latest.json`) are for the app's built-in updater. You don't need to download them.

### Before you install

- The Windows installers aren't code-signed yet, so Windows SmartScreen may warn you. Choose **More info**, then **Run anyway**.
- The macOS app isn't notarized yet. After the first launch is blocked, open **System Settings > Privacy & Security** and choose **Open Anyway**.

## Updates

YogurtSQL checks for a new version every hour, downloads it in the background, and asks you to restart. You can turn this off in **Settings > Updates**. Every update is signed, and the app installs one only if its signature matches the key built into it.

If you installed version 0.2.1 or earlier, it can't find updates anymore. Install the latest version from Releases once; your connections and settings are kept.

## Feedback and security

- Report a bug or ask for a feature in [Issues](https://github.com/SaqibZafar/yogurtsql-releases/issues). Please include your version (**Settings > About**) and your system.
- Report a security problem privately, not in an issue. See [SECURITY.md](SECURITY.md).

## License

YogurtSQL is proprietary software, free to use under its [license agreement](LICENSE). Copyright (c) 2026 M Saqib Zafar. All rights reserved.

The open-source software YogurtSQL is built with is listed, with its licenses, in the app under **Settings > About**.
