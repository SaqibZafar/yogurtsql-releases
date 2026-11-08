# Security policy

## Reporting a vulnerability

Please don't open a public issue. Report it privately instead: on this repository's **Security** tab, choose **Report a vulnerability**. Include the version, your system, and the steps to reproduce.

You'll get a reply within a week. Fixes ship as a normal release, and installed apps update themselves within an hour of it being published.

## Supported versions

Only the latest release gets security fixes. Automatic updates are on by default (**Settings > Updates**).

## Scope

In scope:
- the desktop app,
- its update channel (the signed releases and `latest.json` in this repository),
- the vault and backup file formats.

Things that are not vulnerabilities:
- **Running SQL you typed.** You can run any SQL you type on a server you can sign in to; that's what the app is for.
- **Same-user access.** Software already running as you on an unlocked computer can read the system keychain. The Settings page says so for the keychain and biometric options.
