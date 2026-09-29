# AppBlockingMacOS

Shell script that generates an **Intune Settings Catalog policy (JSON)** for the
macOS 27 Declarative Device Management app configuration
(`AllowedBinaries` / `DeniedBinaries`), based on the apps installed on a Mac.

When `AllowedBinaries` is active, nothing runs on the device unless a policy
explicitly allows it. Run this script on a reference/test device to collect
the signing attributes of all apps and import the result into Intune.

## Requirements

- macOS 27 or later
- No Xcode or Command Line Tools needed (uses `codesign`, `file`, `openssl`,
  `plutil` and `log`, all part of macOS)
- Reading the log (`--log`, log check in allow mode) needs admin rights. If
  the current user can't read the log store, the script asks for the sudo
  password.

## Usage

```bash
chmod +x create_app_policy.sh

./create_app_policy.sh                     # interactive, writes a JSON policy
./create_app_policy.sh "/Applications/Citrix Workspace.app"   # show values of one app
./create_app_policy.sh --log               # blocked apps (asks: live or last 8h)
./create_app_policy.sh --log -l            # live view of blocked apps
./create_app_policy.sh --log -p            # blocked apps of the last 8 hours
./create_app_policy.sh --help
```

### Interactive mode

1. **CDHash yes/no.** Without CDHash (recommended) the rules use Team ID,
   Signing ID and path, so they keep working after app updates. A CDHash
   matches exactly one version, so every app update needs a policy update.
2. **Mode**
   - `AllowedBinaries`: only allowed apps run. You can allow all Apple-signed
     binaries (`*APPLE*`), set `AlwaysAllowManagedApps`, and either scan the
     whole system or enter single apps.
     Afterwards the script can check the log of the last 8 hours for blocked
     binaries that aren't in the policy yet, and add all, none or selected ones.
     Binaries inside an app bundle are added as the whole (outermost) bundle.
     Translocated or deleted apps are skipped.
   - `DeniedBinaries`: everything runs except the apps you enter.
3. **Output.** Import the JSON in *Intune > Devices > Configuration > Import
   policy*. When you enter single apps, the script also prints the values
   for manual entry in Intune.

The full system scan looks in `/Applications`, `~/Applications`,
`/Library/Application Support`, `/Library/SystemExtensions`,
`/Library/PrivilegedHelperTools`, `/usr/local/bin` and at all binaries
started by third-party LaunchDaemons/LaunchAgents.

### Show values of one app

With a path argument the script prints Path Prefix, Signing ID, Signing
State, Team ID and the CDHash per architecture. No policy file is written.

### Blocked apps log

Blocks are logged by `managedeventsd`. The script filters the unified log,
normalizes App Translocation paths (apps started from a DMG or Downloads) and
groups repeated blocks with a count.

```
log show --last 8h --style compact --predicate 'subsystem == "com.apple.devicemanagementclient.managedeventsd" AND category == "LaunchPolicy" AND eventMessage CONTAINS "DENIED"'
```

## Signing State

Determined as described in Apple's documentation:

| Source | Signing State | Intune value |
|---|---|---|
| Authority `Software Signing` / `macOS Software Signing` | Apple | `_5` |
| Authority `Apple Mac OS Application Signing` | AppStore | `_4` |
| OID `1.2.840.113635.100.6.1.25.1` | TestFlight | `_1` |
| OID `1.2.840.113635.100.6.1.9` | AppStore | `_4` |
| OID `1.2.840.113635.100.6.1.13` | DeveloperID | `_2` |
| OID `1.2.840.113635.100.6.1.4` | Enterprise | `_3` |
| unknown | All (omitted) | – |

Unsigned, ad hoc and development-signed binaries (OID `…6.1.12`) can't be
matched and are skipped.

## Limitations

- Without CDHash, the Team ID of an app's main binary covers the whole
  bundle. If a helper inside the bundle has a different Team ID, use the
  CDHash mode.
- Apps started from outside `/Applications` may run from a random
  App Translocation path, so Path Prefix rules won't match them.

## References

- [Apple: Allowing and denying apps and binaries](https://developer.apple.com/documentation/devicemanagement/allowing-and-denying-apps-and-binaries)
- [Apple Platform Deployment: Allow and deny apps and binaries](https://support.apple.com/guide/deployment/dep001044b08/web)
