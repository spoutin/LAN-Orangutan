(function (root, factory) {
    const refresh = factory();
    if (typeof module === 'object' && module.exports) module.exports = refresh;
    root.scanRefresh = refresh;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    function completedNetworkKeys(progress) {
        const quick = (progress.networks || []).map(network => `quick:${network.network}:${network.status}`);
        const deep = (progress.deep_networks || [])
            .filter(network => network.total > 0 && network.complete === network.total && network.active === 0)
            .map(network => `deep:${network.network}`);
        return [...quick, ...deep];
    }

    function automaticScanFailureMessage(progress) {
        if (!progress || !progress.automatic) return null;
        const failed = (progress.networks || []).filter(n => n.status === 'failed');
        if (failed.length === 0) return null;
        const failedNames = failed.map(n => n.network_name || n.network).join(', ');
        const firstErr = failed[0].error || 'scanner failure';
        return `Scan failed for ${failedNames}: ${firstErr}`;
    }

    function scannedSubnetCount(progress) {
        if (!progress) return 0;
        if (typeof progress.scanned_network_count === 'number' && progress.scanned_network_count >= 0) {
            return progress.scanned_network_count;
        }
        return (progress.networks || []).filter(n => !n.is_supplemental && n.status === 'scanned').length;
    }

    function formatScanCompletionSummary(progress) {
        if (!progress) return '';
        const count = scannedSubnetCount(progress);
        const total = progress.network_count || count;
        const where = total > 1 ? ` across ${count} network${count === 1 ? '' : 's'}` : '';
        const devCount = progress.device_count || 0;
        return `Found ${devCount} device${devCount === 1 ? '' : 's'}${where}`;
    }

    return { completedNetworkKeys, automaticScanFailureMessage, scannedSubnetCount, formatScanCompletionSummary };
});
