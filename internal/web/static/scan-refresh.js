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
        const devCount = progress.device_count || 0;
        const devText = `Found ${devCount} device${devCount === 1 ? '' : 's'}`;

        const skipped = (progress.networks || []).filter(n => !n.is_supplemental && n.status === 'skipped');
        const failed = (progress.networks || []).filter(n => !n.is_supplemental && n.status === 'failed');

        if (total <= 1) {
            if (failed.length > 0) {
                const failReason = failed[0].error ? `: ${failed[0].error}` : '';
                return `Scan failed for ${failed[0].network_name || failed[0].network}${failReason}`;
            }
            return devText;
        }

        if (count === total && failed.length === 0 && skipped.length === 0) {
            return `${devText} across ${total} networks`;
        }

        const details = [];
        if (skipped.length > 0) {
            const reason = skipped[0].error ? `: ${skipped[0].error}` : '';
            details.push(`${skipped.length} skipped${reason}`);
        }
        if (failed.length > 0) {
            const failNames = failed.map(f => f.network_name || f.network).join(', ');
            details.push(`${failed.length} failed: ${failNames}`);
        }
        const note = details.length > 0 ? ` (${details.join(', ')})` : '';
        return `${devText} across ${count} of ${total} networks${note}`;
    }

    return { completedNetworkKeys, automaticScanFailureMessage, scannedSubnetCount, formatScanCompletionSummary };
});
