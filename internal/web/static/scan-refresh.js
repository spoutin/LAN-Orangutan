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

    return { completedNetworkKeys };
});
