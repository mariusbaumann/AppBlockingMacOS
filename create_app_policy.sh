#!/bin/bash
# Creates an Intune Settings Catalog policy (JSON) for macOS 27 DDM
# AllowedBinaries / DeniedBinaries based on the apps on this device.
# Docs: https://developer.apple.com/documentation/devicemanagement/allowing-and-denying-apps-and-binaries
# Usage: see ./create_app_policy.sh --help

usage() {
  cat <<EOF
Usage: ${0##*/} [option | path]

Creates an Intune Settings Catalog policy (JSON) for the macOS 27 DDM
app configuration (AllowedBinaries / DeniedBinaries) from the apps on this Mac.

  (no argument)      Interactive: choose CDHash yes/no, allow or deny mode,
                     full system scan or single apps. Writes a JSON file for
                     Intune > Devices > Configuration > Import policy.
  <path>             Only show the values of one app or binary
                     (Path Prefix, Signing ID, Signing State, Team ID, CDHash
                     per architecture) for manual entry in Intune.
  --log              Show apps blocked by the policy (asks: live or last 8h).
  --log -l           Live view of blocked apps (Ctrl+C to stop).
  --log -p           Blocked apps of the last 8 hours, grouped with count.
  -h, --help         Show this help.

Examples:
  ${0##*/}
  ${0##*/} "/Applications/Citrix Workspace.app"
  ${0##*/} --log -p

Notes:
  - Without CDHash (recommended) rules use Team ID / Signing ID / path and
    survive app updates. CDHash rules match exactly one version.
  - Unsigned, ad hoc and development-signed binaries can't be matched and are
    skipped.
  - Blocked apps are logged by managedeventsd
    (subsystem com.apple.devicemanagementclient.managedeventsd).
EOF
}

ask() { # question default -> REPLY
  read -r -p "$1 [$2]: " REPLY
  REPLY=${REPLY:-$2}
}
is_yes() { case $1 in [jJyY]*) return 0;; *) return 1;; esac; }
warn() { echo "  ! $*" >&2; }

esc() { local s=${1//\\/\\\\}; printf '%s' "${s//\"/\\\"}"; }

simple() {
  printf '{"@odata.type":"#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance","settingDefinitionId":"%s","simpleSettingValue":{"@odata.type":"#microsoft.graph.deviceManagementConfigurationStringSettingValue","value":"%s"}}' "$1" "$(esc "$2")"
}
group() {
  printf '{"@odata.type":"#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance","settingDefinitionId":"%s","groupSettingCollectionValue":[%s]}' "$1" "$2"
}
choice() {
  printf '{"@odata.type":"#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance","settingDefinitionId":"%s","choiceSettingValue":{"value":"%s","children":[]}}' "$1" "$2"
}

ENTRIES=() TEXTS=()
STATES=(All TestFlight DeveloperID Enterprise AppStore Apple) # Intune index -> name
add_entry() { # cdhash signingid teamid pathprefix signingstate (empty = omit)
  local k=app_allowed_$KIND c=() e
  [ -n "$1" ] && c+=("$(simple ${k}_item_cdhash "$1")")
  [ -n "$4" ] && c+=("$(simple ${k}_item_pathprefix "$4")")
  [ -n "$2" ] && c+=("$(simple ${k}_item_signingid "$2")")
  [ -n "$5" ] && c+=("$(choice ${k}_item_signingstate ${k}_item_signingstate_$5)")
  [ -n "$3" ] && c+=("$(simple ${k}_item_teamid "$3")")
  e="{\"children\":[$(IFS=,; echo "${c[*]}")]}"
  for x in "${ENTRIES[@]}"; do [ "$x" = "$e" ] && return; done
  ENTRIES+=("$e")
  TEXTS+=("$(
    [ -n "$1" ] && echo "  CDHash:        $1"
    [ -n "$4" ] && echo "  Path Prefix:   $4"
    [ -n "$2" ] && echo "  Signing ID:    $2"
    [ -n "$5" ] && echo "  Signing State: ${STATES[$5]}"
    [ -n "$3" ] && echo "  Team ID:       $3"
  )")
}

# SigningState per Apple docs: first Authority, for Developer ID / Apple Distribution
# the OIDs of the leaf certificate. Intune index = order in the Apple schema:
# 0 All, 1 TestFlight, 2 DeveloperID, 3 Enterprise, 4 AppStore, 5 Apple
signing_state() { # codesign-output path [arch] -> STATE; return 1 = development
  local oids
  STATE=
  case $(sed -n 's/^Authority=//p' <<<"$1" | head -1) in
    "Software Signing"|"macOS Software Signing") STATE=5; return ;;
    "Apple Mac OS Application Signing") STATE=4; return ;;
  esac
  rm -f "$TMP".c*
  codesign -d ${3:+--arch "$3"} --extract-certificates="$TMP.c" "$2" 2>/dev/null
  oids=$(openssl x509 -inform DER -in "$TMP.c0" -noout -text 2>/dev/null | grep -oE '1\.2\.840\.113635\.100\.6\.1\.[0-9.]+')
  case $'\n'$oids$'\n' in
    *$'\n'1.2.840.113635.100.6.1.12$'\n'*) return 1 ;;
    *$'\n'1.2.840.113635.100.6.1.25.1$'\n'*) STATE=1 ;;
    *$'\n'1.2.840.113635.100.6.1.9$'\n'*) STATE=4 ;;
    *$'\n'1.2.840.113635.100.6.1.13$'\n'*) STATE=2 ;;
    *$'\n'1.2.840.113635.100.6.1.4$'\n'*) STATE=3 ;;
  esac # unknown -> empty = All
}

# Sets SIGID TEAM CDH STATE. Return 1 = not usable (unsigned, ad hoc, development).
sig_info() { # path [arch]
  local out
  out=$(codesign -dvvv ${2:+--arch "$2"} "$1" 2>&1) || return 1
  grep -q '^Signature=adhoc' <<<"$out" && return 1
  grep -q '^Authority=Apple Development' <<<"$out" && return 1
  signing_state "$out" "$1" "$2" || return 1
  SIGID=$(sed -n 's/^Identifier=//p' <<<"$out")
  TEAM=$(sed -n 's/^TeamIdentifier=//p' <<<"$out")
  CDH=$(sed -n 's/^CDHash=//p' <<<"$out")
  case $TEAM in ""|"not set") TEAM='*APPLE*';; esac
}

# Architectures (slices) of a Mach-O binary via file (lipo needs the developer tools).
# Empty output = not Mach-O.
archs() {
  local f
  f=$(file -b "$1" 2>/dev/null | head -1)
  case $f in
    *"universal binary"*) grep -oE '\[[^]:]+' <<<"$f" | cut -c2- ;;
    Mach-O*) echo "${f##* }" ;;
  esac
}

# All executable Mach-O files of a bundle (no dylibs/frameworks).
bundle_execs() {
  find "$1" -type f -perm +111 2>/dev/null | while IFS= read -r f; do
    file -b "$f" | grep -q 'Mach-O.*executable' && echo "$f"
  done
}

process() { # .app/.systemextension or single binary
  local item=$1 exe a
  [ -d "$item" ] || [ -n "$(archs "$item")" ] || return # scripts etc.
  echo "- $item"
  if [ "$USE_HASH" = 1 ]; then
    if [ -d "$item" ]; then bundle_execs "$item"; else echo "$item"; fi | while IFS= read -r exe; do
      for a in $(archs "$exe"); do
        if sig_info "$exe" "$a"; then echo "$CDH|$SIGID|$TEAM|$STATE"; else warn "skipped (unsigned/ad hoc/dev): $exe ($a)"; fi
      done
    done > "$TMP"
    while IFS='|' read -r c s t st; do add_entry "$c" "$s" "$t" "" "$st"; done < "$TMP"
    return
  fi
  sig_info "$item" || { warn "skipped (unsigned/ad hoc/dev): $item"; return; }
  if [ "$KIND" = deniedbinaries ]; then
    add_entry "" "$SIGID" "$TEAM" "" "$STATE"
  else
    [ "$TEAM" = '*APPLE*' ] && [ "$APPLE_RULE" = 1 ] && return
    # ponytail: main binary's TeamID covers the whole bundle; helpers with a different TeamID -> use hash mode
    [ -d "$item" ] && add_entry "" "" "$TEAM" "$item/" "$STATE" || add_entry "" "" "$TEAM" "$item" "$STATE"
  fi
}

# Sensible locations: app folders, Application Support, system extensions,
# helper tools and all binaries started via LaunchDaemon/-Agent.
scan_items() {
  local d p f
  for d in /Applications /Users/*/Applications "/Library/Application Support" /Library/SystemExtensions; do
    [ -d "$d" ] && find "$d" -maxdepth 4 -type d \( -name '*.app' -o -name '*.systemextension' \) -print -prune 2>/dev/null
  done
  for d in /Library/PrivilegedHelperTools /usr/local/bin; do
    [ -d "$d" ] && find "$d" -maxdepth 1 -type f 2>/dev/null
  done
  for f in /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist /Users/*/Library/LaunchAgents/*.plist; do
    [ -f "$f" ] || continue
    p=$(plutil -extract Program raw -o - "$f" 2>/dev/null || plutil -extract ProgramArguments.0 raw -o - "$f" 2>/dev/null) || continue
    case $p in
      /System/*|/usr/bin/*|/bin/*|/usr/sbin/*|/sbin/*|/usr/libexec/*) ;; # Apple
      *.app/*) echo "${p%%.app/*}.app" ;;
      /*) [ -f "$p" ] && echo "$p" ;;
    esac
  done
}

ask_app() { # -> APP (existing path)
  while :; do
    # without -r: "Citrix\ Workspace.app" (tab/drag & drop) becomes "Citrix Workspace.app"
    read -e -p "Path to app (e.g. /Applications/Claude.app): " APP
    APP=${APP#[\"\']}; APP=${APP%[\"\']}; APP=${APP%/}
    [ -e "$APP" ] && return
    echo "Path does not exist."
  done
}

# ---------- Main ----------
case $1 in -h|--help) usage; exit 0 ;; esac

TMP=$(mktemp); trap 'rm -f "$TMP" "$TMP".c*' EXIT

# --log: blocks by managedeventsd from the unified log. Translocation paths
# (apps run directly from DMG/Downloads) have random UUIDs -> normalized.
if [ "$1" = --log ]; then
  PRED='subsystem == "com.apple.devicemanagementclient.managedeventsd" AND category == "LaunchPolicy" AND eventMessage CONTAINS "DENIED"'
  NORM='/DENIED exec:/ { p=$0; sub(/.*, path /,"",p); sub(/.*\/AppTranslocation\/[^\/]*\/d\//,"[AppTranslocation]/",p); t=substr($1" "$2,1,19)'
  case $2 in
    -l) MODE=l ;; -p) MODE=p ;;
    *) echo "  1) Live"; echo "  2) Last 8 hours"; ask "Choice" 1; [ "$REPLY" = 2 ] && MODE=p || MODE=l ;;
  esac
  if [ "$MODE" = p ]; then
    echo "Blocked in the last 8h (last seen | count | path):"
    log show --last 8h --style compact --predicate "$PRED" | awk "$NORM"'; n[p]++; l[p]=t }
      END { for (p in n) printf "%s  %4dx  %s\n", l[p], n[p], p }' | sort
  else
    echo "Live - blocked apps (Ctrl+C to stop), repeats are counted:"
    log stream --style compact --predicate "$PRED" | awk "$NORM"'; n[p]++
      if (n[p] == 1) printf "%s  BLOCKED       %s\n", t, p
      else printf "%s  again (%dx)   %s\n", t, n[p], p
      fflush() }'
  fi
  exit 0
fi

# With path argument: only show values, no policy
if [ -n "$1" ]; then
  APP=${1%/}
  [ -e "$APP" ] || { echo "Path does not exist: $APP (see --help)"; exit 1; }
  sig_info "$APP" || { echo "Not usable (unsigned/ad hoc/development): $APP"; exit 1; }
  exe=$(codesign -d "$APP" 2>&1 | sed -n 's/^Executable=//p')
  echo "=== $APP ==="
  echo "  Path Prefix:   $APP$([ -d "$APP" ] && echo /)"
  echo "  Signing ID:    $SIGID"
  echo "  Signing State: ${STATES[${STATE:-0}]}"
  echo "  Team ID:       $TEAM"
  for a in $(archs "$exe"); do
    sig_info "$APP" "$a" && echo "  CDHash ($a): $CDH"
  done
  echo
  echo "Allowed Binaries: Team ID (required) + optional Path Prefix / Signing ID / Signing State"
  echo "Denied Binaries:  Signing ID or Team ID (required) + optional Path Prefix / Signing State"
  echo "CDHash only matches this version and only the main binary (helpers: interactive mode with CDHash)."
  exit 0
fi

echo "=== macOS DDM App Policy Generator (Intune) ==="
echo
echo "Use CDHash?"
echo "  Without (recommended): rules based on TeamID/SigningID/path, survive app updates."
echo "  With: WARNING - each CDHash matches exactly one version. Every app update"
echo "        requires a policy update, otherwise the app gets blocked (allow mode)."
ask "Use CDHash? (y/n)" n; is_yes "$REPLY" && USE_HASH=1 || USE_HASH=0
echo
echo "Mode:"
echo "  1) AllowedBinaries - only explicitly allowed apps run"
echo "  2) DeniedBinaries  - everything runs except explicitly denied apps"
ask "Choice" 2
if [ "$REPLY" = 1 ]; then
  KIND=allowedbinaries
  echo
  echo "NOTE: In AllowedBinaries mode ALL apps have to be allowed explicitly."
  echo "Apps not listed (except essential OS binaries) will be blocked."
  ask "Allow all Apple-signed binaries (TeamID *APPLE*)? (y/n)" y
  is_yes "$REPLY" && APPLE_RULE=1 || APPLE_RULE=0
  ask "Always allow managed apps (Intune) - AlwaysAllowManagedApps? (y/n)" y
  is_yes "$REPLY" && MANAGED=true || MANAGED=false
  echo "  1) Scan whole system"
  echo "  2) Specify single app"
  ask "Choice" 1
  [ "$APPLE_RULE" = 1 ] && add_entry "" "" '*APPLE*' ""
  if [ "$REPLY" = 1 ]; then
    echo "Scanning ..."
    while IFS= read -r i; do process "$i"; done < <(scan_items | sort -u)
  else
    SINGLE=1
    while :; do ask_app; process "$APP"; ask "Another app? (y/n)" n; is_yes "$REPLY" || break; done
  fi
else
  KIND=deniedbinaries
  SINGLE=1
  while :; do ask_app; process "$APP"; ask "Deny another app? (y/n)" n; is_yes "$REPLY" || break; done
fi

[ ${#ENTRIES[@]} -eq 0 ] && { echo "No entries created - aborting."; exit 1; }

echo
ask "Policy name" "macOS_$([ $KIND = allowedbinaries ] && echo Allow || echo Block)Apps_$(date +%Y-%m-%d)"
NAME=$REPLY
ask "Output file" "./$NAME.json"
OUT=$REPLY

INNER=$(group app_allowed_$KIND "$(IFS=,; echo "${ENTRIES[*]}")")
[ "$KIND" = allowedbinaries ] && INNER="$INNER,$(choice app_allowed_alwaysallowmanagedapps app_allowed_alwaysallowmanagedapps_$MANAGED)"
SETTING=$(group app_app "{\"children\":[$(group app_allowed "{\"children\":[$INNER]}")]}")

printf '{"name":"%s","description":"Generated by create_app_policy.sh on %s","platforms":"macOS","technologies":"mdm,appleRemoteManagement","roleScopeTagIds":["0"],"templateReference":{"templateId":""},"settings":[{"id":"0","settingInstance":%s}]}\n' \
  "$(esc "$NAME")" "$(esc "$(hostname)")" "$SETTING" > "$OUT"

plutil -convert xml1 -o /dev/null "$OUT" || { echo "ERROR: invalid JSON in $OUT"; exit 1; }
echo
echo "${#ENTRIES[@]} entries written: $OUT"
echo "Import: Intune > Devices > Configuration > Import policy"
if [ "$SINGLE" = 1 ]; then
  echo
  echo "=== Values for manual entry ($([ $KIND = allowedbinaries ] && echo Allowed || echo Denied) Binaries) ==="
  for i in "${!TEXTS[@]}"; do echo "Entry $((i+1)):"; echo "${TEXTS[$i]}"; done
fi
