# Compatibility cleanup for installations made before rsync was removed.
tc_rsync_enabled() { return 1; }

tc_stop_rsync_if_running() {
    if runtime_process_present_by_ucomm "$RSYNC_PROC_NAME"; then
        stop_runtime_process_by_ucomm "$RSYNC_PROC_NAME" "$RSYNC_PROC_NAME" || return 1
    fi
}

tc_manager_clear_rsync_runtime() {
    tc_stop_rsync_if_running || return 1
    rm -f "$TC_RSYNC_BIN" "$TC_RSYNC_CONF" >/dev/null 2>&1 || return 1
    TC_MANAGER_LAST_RSYNC_SIGNATURE=
}

tc_manager_reconcile_rsync() {
    tc_manager_clear_rsync_runtime
}
