(function (root, factory) {
    const mod = factory();
    if (typeof module === 'object' && module.exports) module.exports = mod;
    root.deviceOperationState = mod;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    function shouldSyncSidebarForm({ hasUnsavedChanges, isFormFocused }) {
        return !hasUnsavedChanges && !isFormFocused;
    }

    function isElementProtectedFromTimeUpdate(el) {
        if (!el) return true;
        if (typeof el.closest === 'function' && (el.closest('.deep-scan-progress') || el.closest('.scanning'))) {
            return true;
        }
        return false;
    }

    function formatLastDeepScan(isoDateString, isScanning) {
        if (isScanning) {
            return {
                html: '<span class="deep-scan-progress"><svg class="spinner-svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/></svg>Scanning services...</span>',
                hasRelativeTime: false,
                unix: null,
            };
        }
        if (!isoDateString) {
            return {
                html: 'Never',
                hasRelativeTime: false,
                unix: null,
            };
        }
        const scannedAt = new Date(isoDateString);
        if (isNaN(scannedAt.getTime())) {
            return {
                html: 'Never',
                hasRelativeTime: false,
                unix: null,
            };
        }
        const unix = Math.floor(scannedAt.getTime() / 1000);
        return {
            html: `${scannedAt.toLocaleString()} · <span class="scan-time-relative" data-relative-time="${unix}"></span>`,
            hasRelativeTime: true,
            unix: unix,
        };
    }

    return {
        shouldSyncSidebarForm,
        isElementProtectedFromTimeUpdate,
        formatLastDeepScan,
    };
});
