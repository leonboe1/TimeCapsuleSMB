tc_stop_telemetry_schedulers() {
    # Never escalate to KILL: a telemetry process may still own a debug child.
    # Match live processes rather than trusting a PID cached by an old manager.
    /usr/bin/pkill '^telemetry$' >/dev/null 2>&1 || true
    /usr/bin/pkill '^heartbeat$' >/dev/null 2>&1 || true
}

tc_legacy_telemetry_users_present() {
    legacy_ps=$(/bin/ps ax -o stat= -o ucomm= 2>/dev/null) || return 2
    while read -r legacy_stat legacy_command legacy_rest; do
        case "$legacy_stat" in Z*|"") continue ;; esac
        case "$legacy_command" in telemetry|debug|heartbeat) return 0 ;; esac
    done <<EOF
$legacy_ps
EOF
    return 1
}

tc_cleanup_legacy_telemetry() {
    # Always check users, even when the old workspace is absent.
    legacy_attempt=0
    while :; do
        if tc_legacy_telemetry_users_present; then
            legacy_status=0
        else
            legacy_status=$?
        fi
        case "$legacy_status" in
            1) break ;;
            2) echo "telemetry: cannot inspect legacy workspace users" >&2; return 1 ;;
        esac
        if [ "$legacy_attempt" -ge 5 ]; then
            echo "telemetry: legacy debug work is still active; restart the device before retrying" >&2
            return 75
        fi
        legacy_attempt=$((legacy_attempt + 1))
        sleep 1
    done
    # An arbitrary detached debug worker may inherit the directory lock and
    # rename itself. Shell process names cannot establish lock ownership. Never
    # execute an old helper to ask it to clean up; a restart clears these RAM
    # files and any surviving worker before migration can proceed.
    for cleanup_path in "/mnt/Memory/debug" "/mnt/Memory/debug.sig"; do
        if [ -e "$cleanup_path" ] || [ -L "$cleanup_path" ]; then
            echo "telemetry: debug files remain; restart the device before retrying" >&2
            return 1
        fi
    done
    legacy_root="/mnt/Memory/tc-telemetry"
    [ -e "$legacy_root" ] || [ -L "$legacy_root" ] || return 0
    if [ -L "$legacy_root" ] || [ ! -d "$legacy_root" ]; then
        echo "telemetry: refusing unexpected legacy workspace type: $legacy_root" >&2
        return 1
    fi
    legacy_mounts=$(/sbin/mount 2>/dev/null) || {
        echo "telemetry: cannot inspect legacy workspace mounts" >&2
        return 1
    }
    while IFS= read -r legacy_mount; do
        case "$legacy_mount" in
            *" on $legacy_root "*|*" on $legacy_root/"*)
                echo "telemetry: refusing cleanup of a mounted legacy workspace" >&2
                return 1
                ;;
        esac
    done <<EOF
$legacy_mounts
EOF
    # One-time migration only. rm does not follow symlinks within this verified
    # application tree. New telemetry never creates a job directory.
    /bin/rm -rf "$legacy_root" || {
        echo "telemetry: could not remove legacy workspace" >&2
        return 1
    }
}

tc_prepare_telemetry_reset() {
    tc_stop_telemetry_schedulers
    tc_cleanup_legacy_telemetry
}

tc_cleanup_telemetry_for_uninstall() {
    tc_prepare_telemetry_reset
}
