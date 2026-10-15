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

    function formatDeltaSeconds(sec, isPast) {
        if (sec < 5) return isPast ? 'just now' : 'due now';
        if (sec < 60) return isPast ? `${sec}s ago` : `in ${sec}s`;
        const mins = Math.round(sec / 60);
        if (mins < 60) return isPast ? `${mins}m ago` : `in ~${mins}m`;
        const hours = Math.round(mins / 60);
        return isPast ? `${hours}h ago` : `in ~${hours}h`;
    }

    function formatRefreshCountdown(options) {
        const opts = options || {};
        if (!opts.continuousScan) {
            return 'refresh paused';
        }
        if (opts.isRefreshing || typeof opts.secondsRemaining !== 'number' || opts.secondsRemaining <= 0) {
            return 'refreshing...';
        }
        return `refresh in ${opts.secondsRemaining}s`;
    }

    function formatRefreshTooltip(options) {
        const opts = options || {};
        const nowMs = typeof opts.nowMs === 'number' ? opts.nowMs : Date.now();
        const lines = ['Network Scan:'];

        if (!opts.lastScanUnix) {
            lines.push('  • Last scan: Not scanned yet');
        } else {
            const lastScanSec = Math.max(0, Math.floor(nowMs / 1000 - opts.lastScanUnix));
            lines.push(`  • Last scan: ${formatDeltaSeconds(lastScanSec, true)}`);
        }

        if (opts.isScanRunning) {
            lines.push('  • Next scan: In progress...');
        } else if (!opts.continuousScan) {
            lines.push('  • Next scan: Paused (manual only)');
        } else if (opts.nextScanUnix && opts.nextScanUnix > 0) {
            const nextScanSec = Math.floor(opts.nextScanUnix - nowMs / 1000);
            if (nextScanSec <= 0) {
                lines.push('  • Next scan: Due any moment');
            } else {
                lines.push(`  • Next scan: ${formatDeltaSeconds(nextScanSec, false)}`);
            }
        } else {
            lines.push('  • Next scan: Scheduled when active');
        }

        lines.push('');
        lines.push('Dashboard Refresh:');

        if (opts.lastRefreshTimeMs) {
            const lastRefSec = Math.max(0, Math.floor((nowMs - opts.lastRefreshTimeMs) / 1000));
            lines.push(`  • Last updated: ${formatDeltaSeconds(lastRefSec, true)}`);
        } else {
            lines.push('  • Last updated: Just now');
        }

        if (!opts.continuousScan) {
            lines.push('  • Next refresh: Paused');
        } else if (opts.nextRefreshTimeMs) {
            const nextRefSec = Math.floor((opts.nextRefreshTimeMs - nowMs) / 1000);
            if (nextRefSec <= 0) {
                lines.push('  • Next refresh: Refreshing...');
            } else {
                lines.push(`  • Next refresh: in ${nextRefSec}s`);
            }
        } else {
            lines.push('  • Next refresh: in ~30s');
        }

        return lines.join('\n');
    }

    return {
        completedNetworkKeys,
        automaticScanFailureMessage,
        scannedSubnetCount,
        formatScanCompletionSummary,
        formatRefreshCountdown,
        formatRefreshTooltip
    };
});
