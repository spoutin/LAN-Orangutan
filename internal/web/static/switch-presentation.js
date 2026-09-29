(function (root, factory) {
    const presentation = factory();
    if (typeof module === 'object' && module.exports) module.exports = presentation;
    root.switchConnectionPresentation = presentation.switchConnectionPresentation;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    function switchConnectionPresentation(data) {
        const connectionText = (data.switchPort || '').trim();
        if (!connectionText) return { visible: false };

        const isUplink = /^po\d+$/i.test(connectionText);
        const isWirelessClient = !!(data.ssid || '').trim();
        const poeWatts = Number(data.switchPoeWatts);

        return {
            visible: true,
            title: isUplink ? 'Switch Uplink' : isWirelessClient ? 'Upstream AP Connection' : 'Switch Connection',
            connectionText,
            interfaceLabel: isUplink ? 'Interface:' : isWirelessClient ? 'AP Port:' : 'Port:',
            showVLAN: !isUplink,
            showLink: !isUplink,
            showPoE: data.switchPoeWatts !== '' && !isNaN(poeWatts)
        };
    }

    return { switchConnectionPresentation };
});
