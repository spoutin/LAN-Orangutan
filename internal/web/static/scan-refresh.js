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

    return { completedNetworkKeys, automaticScanFailureMessage };
});
