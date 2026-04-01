#!/usr/bin/env bash
# =============================================================================
# macOS Security Scan Script for GoldQuant
# Checks for known macOS malware/RAT indicators, suspicious persistence
# mechanisms, and common threat artifacts.
#
# Usage: bash security-scan.sh [--quick] [--verbose]
#   --quick    Only check critical indicators (skip deep scans)
#   --verbose  Show all checks, including clean results
#
# Must be run on macOS. Some checks require sudo for full coverage.
# =============================================================================

set -euo pipefail

# --- Colors & Formatting ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

QUICK=false
VERBOSE=false
FINDINGS=0
WARNINGS=0

for arg in "$@"; do
    case "$arg" in
        --quick)   QUICK=true ;;
        --verbose) VERBOSE=true ;;
    esac
done

banner() {
    echo ""
    echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}${BOLD}  $1${NC}"
    echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

finding() {
    echo -e "  ${RED}[!] FINDING:${NC} $1"
    FINDINGS=$((FINDINGS + 1))
}

warning() {
    echo -e "  ${YELLOW}[~] WARNING:${NC} $1"
    WARNINGS=$((WARNINGS + 1))
}

clean() {
    if $VERBOSE; then
        echo -e "  ${GREEN}[+]${NC} $1"
    fi
}

info() {
    echo -e "  ${BLUE}[*]${NC} $1"
}

check_file() {
    local path="$1"
    local description="$2"
    if [ -e "$path" ]; then
        finding "$description: $path"
    else
        clean "Not found: $path"
    fi
}

# --- Pre-flight ---
IS_MACOS=false
if [[ "$(uname)" == "Darwin" ]]; then
    IS_MACOS=true
fi

echo ""
echo -e "${BOLD}GoldQuant Security Scanner${NC}"
echo -e "Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "Host: $(hostname)"
echo -e "User: $(whoami)"
echo -e "OS:   $(uname -s) $(uname -r)"
if $IS_MACOS; then
    echo -e "macOS: $(sw_vers -productVersion)"
else
    echo -e "${YELLOW}Note: Running on Linux — macOS-specific checks will be skipped.${NC}"
fi

# =========================================================================
# SECTION 1: Known Malware Artifacts (macOS only)
# =========================================================================
if $IS_MACOS; then
banner "1. Known Malware Artifacts"

info "Checking for known RAT/malware file artifacts..."

# CloudMensis / BadRAT
check_file "/Library/Caches/com.apple.act.mond" "CloudMensis RAT artifact"
check_file "/Library/WebServer/share/httpd/manual/softwareupdate" "CloudMensis/DazzleSpy artifact"

# Silver Sparrow
check_file "/tmp/agent.sh" "Silver Sparrow dropper"
check_file "/tmp/version.json" "Silver Sparrow indicator"
check_file "/tmp/version.plist" "Silver Sparrow indicator"
check_file "$HOME/Library/._insu" "Silver Sparrow marker file"

# JokerSpy
check_file "/Users/Shared/.sysmond" "JokerSpy backdoor"
check_file "/Users/Shared/sh.py" "JokerSpy payload"
check_file "$HOME/.local/share/security/update" "JokerSpy persistence"

# KandyKorn (DPRK/Lazarus)
check_file "/Library/com.apple.webkit.cache" "KandyKorn artifact"
check_file "/Users/Shared/.com.apple.systemupdate" "KandyKorn persistence"

# XCSSET
check_file "$HOME/Library/Application Support/.com.apple.protected" "XCSSET hidden directory"

# OSX.Calisto
check_file "$HOME/.calisto" "Calisto RAT directory"

# MacMa (CDDS)
check_file "/var/tmp/.logfile" "MacMa hidden log"

# Pirrit adware
for f in /Library/Application\ Support/com.Pirrit.* "$HOME/.Pirrit"; do
    check_file "$f" "Pirrit adware"
done

# UpdateAgent/WizardUpdate
for f in /Library/Application\ Support/com.apple.framework.*; do
    if [ -e "$f" ]; then
        check_file "$f" "UpdateAgent/WizardUpdate artifact"
    fi
done

fi # end IS_MACOS section 1

# =========================================================================
# SECTION 2: Suspicious LaunchAgents & LaunchDaemons (macOS only)
# =========================================================================
if $IS_MACOS; then
banner "2. LaunchAgents & LaunchDaemons"

LAUNCH_DIRS=(
    "$HOME/Library/LaunchAgents"
    "/Library/LaunchAgents"
    "/Library/LaunchDaemons"
)

# Known malicious plist names
MALICIOUS_PLISTS=(
    "com.apple.act.mond.plist"
    "com.apple.iCloud.FindMyDevice.plist"
    "com.apple.loginhelper.plist"
    "com.apple.softwareupdate.plist"
    "com.apple.services.systemd.plist"
    "com.apple.SafariHelper.plist"
    "com.Pirrit.plist"
    "com.startup.plist"
    "com.UserAgent.System.plist"
    "com.AdditionalTools.plist"
    "com.updater.mcy.plist"
)

for dir in "${LAUNCH_DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        clean "Directory not found: $dir"
        continue
    fi

    info "Scanning $dir ..."

    # Check for known malicious plists
    for plist in "${MALICIOUS_PLISTS[@]}"; do
        check_file "$dir/$plist" "Known malicious plist"
    done

    # Check for hidden plists (leading dot)
    while IFS= read -r -d '' hidden; do
        finding "Hidden plist file: $hidden"
    done < <(find "$dir" -name '.*\.plist' -print0 2>/dev/null)

    # Check plists pointing to suspicious locations
    if ! $QUICK; then
        for plist_file in "$dir"/*.plist; do
            [ -f "$plist_file" ] || continue
            plist_name=$(basename "$plist_file")

            # Check ProgramArguments for suspicious paths
            if plutil -p "$plist_file" 2>/dev/null | grep -qiE '"/tmp/|/Users/Shared/|/var/tmp/|\.local/'; then
                warning "Plist references suspicious path: $plist_name"
            fi

            # Check for script interpreters in ProgramArguments
            if plutil -p "$plist_file" 2>/dev/null | grep -qiE '"(python|osascript|curl|bash -c|perl)"'; then
                warning "Plist uses script interpreter: $plist_name"
            fi
        done
    fi
done

fi # end IS_MACOS section 2

# =========================================================================
# SECTION 3: Suspicious Staging Directories
# =========================================================================
banner "3. Suspicious Files in Staging Directories"

STAGING_DIRS=("/Users/Shared" "/tmp" "/var/tmp")

for dir in "${STAGING_DIRS[@]}"; do
    [ -d "$dir" ] || continue

    # Look for hidden executables
    while IFS= read -r -d '' f; do
        if [ -x "$f" ] || file "$f" 2>/dev/null | grep -q "Mach-O\|executable"; then
            warning "Hidden executable in staging dir: $f"
        fi
    done < <(find "$dir" -maxdepth 2 -name '.*' -type f -print0 2>/dev/null)

    # Look for script files
    while IFS= read -r -d '' f; do
        warning "Script file in staging dir: $f"
    done < <(find "$dir" -maxdepth 2 \( -name '*.sh' -o -name '*.py' -o -name '*.pl' \) -type f -print0 2>/dev/null)
done

# =========================================================================
# SECTION 4: Persistence Mechanisms
# =========================================================================
if ! $QUICK; then
    banner "4. Persistence Mechanisms"

    # Login/Logout Hooks (macOS only)
    if $IS_MACOS; then
        info "Checking login/logout hooks..."
        LOGIN_HOOK=$(defaults read com.apple.loginwindow LoginHook 2>/dev/null || true)
        LOGOUT_HOOK=$(defaults read com.apple.loginwindow LogoutHook 2>/dev/null || true)
        if [ -n "$LOGIN_HOOK" ]; then
            warning "Login hook configured: $LOGIN_HOOK"
        else
            clean "No login hook set"
        fi
        if [ -n "$LOGOUT_HOOK" ]; then
            warning "Logout hook configured: $LOGOUT_HOOK"
        else
            clean "No logout hook set"
        fi
    fi

    # Cron jobs
    info "Checking cron jobs..."
    CRON_OUTPUT=$(crontab -l 2>/dev/null || true)
    if [ -n "$CRON_OUTPUT" ]; then
        warning "User cron jobs found:"
        echo "$CRON_OUTPUT" | while IFS= read -r line; do
            echo "    $line"
        done
    else
        clean "No user cron jobs"
    fi

    # Shell RC persistence
    info "Checking shell profile files for suspicious entries..."
    SHELL_FILES=(
        "$HOME/.zshrc"
        "$HOME/.zshenv"
        "$HOME/.zprofile"
        "$HOME/.bashrc"
        "$HOME/.bash_profile"
    )
    for rc_file in "${SHELL_FILES[@]}"; do
        if [ -f "$rc_file" ]; then
            # Look for suspicious patterns: curl piped to sh, encoded data, etc.
            if grep -qiE 'curl.*\|.*sh|wget.*\|.*sh|base64.*decode|eval.*\$|python.*-c.*import' "$rc_file" 2>/dev/null; then
                warning "Suspicious command in $rc_file"
            fi
        fi
    done

    # Authorization plugins (macOS only)
    if $IS_MACOS; then
        info "Checking authorization plugins..."
        if [ -d "/Library/Security/SecurityAgentPlugins" ]; then
            NON_APPLE=$(find /Library/Security/SecurityAgentPlugins -maxdepth 1 -not -name '.' 2>/dev/null | wc -l)
            if [ "$NON_APPLE" -gt 0 ]; then
                warning "Authorization plugins found in /Library/Security/SecurityAgentPlugins/"
            fi
        fi

        # emond rules
        check_file "/etc/emond.d/rules" "emond rules directory (potential persistence)"
    fi
fi

# =========================================================================
# SECTION 5: Suspicious Processes
# =========================================================================
banner "5. Suspicious Processes"

info "Checking for known malicious process names..."

SUSPICIOUS_PROCS=(
    "mshelper"
    "com.apple.mond"
    "sysmond"
    "swiftd"
    "xmrig"
    "XMRig"
    "MacKeeper"
    "Genieo"
    "Mughthesec"
    "Genio"
    "Conduit"
    "InstallMac"
)

for proc in "${SUSPICIOUS_PROCS[@]}"; do
    if pgrep -f "$proc" >/dev/null 2>&1; then
        finding "Suspicious process running: $proc (PID: $(pgrep -f "$proc" | head -1))"
    else
        clean "Process not found: $proc"
    fi
done

# Check for processes running from suspicious locations
info "Checking for processes running from /tmp, /var/tmp, /Users/Shared..."
ps aux 2>/dev/null | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}' | \
    grep -iE '^(/tmp/|/var/tmp/|/Users/Shared/)' 2>/dev/null | while IFS= read -r line; do
    finding "Process running from suspicious location: $line"
done || true

# =========================================================================
# SECTION 6: Network Connections
# =========================================================================
if ! $QUICK; then
    banner "6. Suspicious Network Connections"

    info "Checking for connections on known malicious ports..."
    SUSPICIOUS_PORTS=(1337 4443 5555 6666 6667 6668 6669 9090 31337)

    for port in "${SUSPICIOUS_PORTS[@]}"; do
        CONNS=$(lsof -iTCP:"$port" -sTCP:ESTABLISHED -n -P 2>/dev/null | tail -n +2 || true)
        if [ -n "$CONNS" ]; then
            warning "Active connection on suspicious port $port:"
            echo "$CONNS" | while IFS= read -r line; do
                echo "    $line"
            done
        fi
    done

    # Check for non-standard processes making outbound connections
    info "Checking for script interpreters with network connections..."
    for interp in python python3 osascript perl ruby; do
        CONNS=$(lsof -i -c "$interp" -n -P 2>/dev/null | grep ESTABLISHED | tail -n +2 || true)
        if [ -n "$CONNS" ]; then
            warning "$interp has active network connections:"
            echo "$CONNS" | head -5 | while IFS= read -r line; do
                echo "    $line"
            done
        fi
    done
fi

# =========================================================================
# SECTION 7: Code Signing Verification
# =========================================================================
if ! $QUICK && $IS_MACOS; then
    banner "7. Code Signing (Spot Check)"

    info "Verifying signatures of running processes from non-system paths..."
    CHECKED=0
    ps -eo pid,comm 2>/dev/null | tail -n +2 | while read -r pid comm; do
        [ -z "$pid" ] && continue
        BINARY=$(ps -p "$pid" -o comm= 2>/dev/null || true)
        [ -z "$BINARY" ] && continue

        # Only check binaries not in /usr/ or /System/
        FULL_PATH=$(ps -p "$pid" -o args= 2>/dev/null | awk '{print $1}' || true)
        if echo "$FULL_PATH" | grep -qvE '^(/usr/|/System/|/sbin/|/bin/)' 2>/dev/null; then
            if [ -f "$FULL_PATH" ] && ! codesign -v "$FULL_PATH" 2>/dev/null; then
                warning "Unsigned binary running: $FULL_PATH (PID: $pid)"
            fi
        fi
        CHECKED=$((CHECKED + 1))
        [ $CHECKED -ge 50 ] && break  # limit to first 50 non-system processes
    done
fi

# =========================================================================
# SECTION 7b: Linux-Specific Checks
# =========================================================================
if ! $IS_MACOS; then
    banner "7b. Linux Security Checks"

    # Check for suspicious cron jobs
    info "Checking cron jobs..."
    CRON_OUTPUT=$(crontab -l 2>/dev/null || true)
    if [ -n "$CRON_OUTPUT" ]; then
        warning "User cron jobs found:"
        echo "$CRON_OUTPUT" | while IFS= read -r line; do
            echo "    $line"
        done
    else
        clean "No user cron jobs"
    fi

    # Check for processes running from /tmp or /dev/shm
    info "Checking for processes running from suspicious locations..."
    ps aux 2>/dev/null | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}' | \
        grep -iE '^(/tmp/|/var/tmp/|/dev/shm/)' 2>/dev/null | while IFS= read -r line; do
        finding "Process running from suspicious location: $line"
    done || true

    # Check for suspicious shell RC entries
    info "Checking shell profiles for suspicious entries..."
    for rc_file in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshrc" "$HOME/.zshenv"; do
        if [ -f "$rc_file" ]; then
            if grep -qiE 'curl.*\|.*sh|wget.*\|.*sh|base64.*decode|eval.*\$|python.*-c.*import' "$rc_file" 2>/dev/null; then
                warning "Suspicious command in $rc_file"
            fi
        fi
    done

    # Check for crypto miners
    info "Checking for known crypto miner processes..."
    for proc in xmrig XMRig minerd cpuminer stratum; do
        if pgrep -f "$proc" >/dev/null 2>&1; then
            finding "Crypto miner process detected: $proc"
        else
            clean "Process not found: $proc"
        fi
    done

    # Check for suspicious network connections (common RAT/C2 ports)
    if ! $QUICK && command -v ss &>/dev/null; then
        info "Checking for connections on suspicious ports..."
        for port in 1337 4443 5555 6666 6667 6668 6669 9090 31337; do
            CONNS=$(ss -tnp "dport = :$port or sport = :$port" 2>/dev/null | tail -n +2 || true)
            if [ -n "$CONNS" ]; then
                warning "Active connection on suspicious port $port:"
                echo "$CONNS" | while IFS= read -r line; do
                    echo "    $line"
                done
            fi
        done
    fi

    # Check for hidden files in /tmp and /dev/shm
    info "Checking for hidden files in staging directories..."
    for dir in /tmp /var/tmp /dev/shm; do
        [ -d "$dir" ] || continue
        while IFS= read -r -d '' f; do
            if [ -x "$f" ] || file "$f" 2>/dev/null | grep -q "ELF\|executable\|script"; then
                warning "Hidden executable in $dir: $f"
            fi
        done < <(find "$dir" -maxdepth 2 -name '.*' -type f -print0 2>/dev/null)
    done
fi

# =========================================================================
# SECTION 8: Project-Specific Checks
# =========================================================================
banner "8. Project Security Checks"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info "Scanning project directory for hardcoded secrets..."

# Check for hardcoded API keys/tokens in Python files
if [ -d "$SCRIPT_DIR" ]; then
    while IFS= read -r match; do
        warning "Potential hardcoded secret: $match"
    done < <(grep -rnE '(api_key|api_secret|token|password|secret)\s*=\s*["\x27][A-Za-z0-9_\-]{16,}["\x27]' \
        --include='*.py' "$SCRIPT_DIR" 2>/dev/null | grep -v '\.env' | grep -v 'os\.environ' | grep -v 'os\.getenv' || true)

    # Check for .env files accidentally committed
    if command -v git &>/dev/null && [ -d "$SCRIPT_DIR/.git" ]; then
        ENV_IN_GIT=$(git -C "$SCRIPT_DIR" ls-files '*.env' '.env*' 2>/dev/null || true)
        if [ -n "$ENV_IN_GIT" ]; then
            finding ".env file tracked by git: $ENV_IN_GIT"
        else
            clean "No .env files tracked by git"
        fi
    fi
fi

# =========================================================================
# SUMMARY
# =========================================================================
banner "Scan Summary"

echo ""
if [ $FINDINGS -gt 0 ]; then
    echo -e "  ${RED}${BOLD}Findings (critical): $FINDINGS${NC}"
else
    echo -e "  ${GREEN}${BOLD}Findings (critical): 0${NC}"
fi

if [ $WARNINGS -gt 0 ]; then
    echo -e "  ${YELLOW}${BOLD}Warnings:            $WARNINGS${NC}"
else
    echo -e "  ${GREEN}${BOLD}Warnings:            0${NC}"
fi

echo ""
if [ $FINDINGS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}System appears clean. No known malware indicators detected.${NC}"
elif [ $FINDINGS -eq 0 ]; then
    echo -e "  ${YELLOW}${BOLD}No critical findings, but review the warnings above.${NC}"
else
    echo -e "  ${RED}${BOLD}Critical findings detected! Review the output above and take action.${NC}"
fi

echo ""
echo -e "  ${BLUE}Scan completed at $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo ""
