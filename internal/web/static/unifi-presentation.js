(function (root, factory) {
    const presentation = factory();
    if (typeof module === 'object' && module.exports) module.exports = presentation;
    root.resolveEffectiveDeviceName = presentation.resolveEffectiveDeviceName;
    root.shouldDisplayUniFiCard = presentation.shouldDisplayUniFiCard;
    root.formatUniFiName = presentation.formatUniFiName;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    function resolveEffectiveDeviceName(data) {
        if (!data) return '';
        const custom = (data.customHostnameOriginal || data.customHostname || '').trim();
        if (custom) return custom;
        const normal = (data.hostnameDisplay || data.hostname || '').trim();
        if (normal) return normal;
        const unifi = (data.unifiNameOriginal || data.unifiName || '').trim();
        if (unifi) return unifi;
        return '';
    }

    function shouldDisplayUniFiCard(data) {
        if (!data) return false;
        return !!((data.ssid || '').trim() || (data.unifiName || '').trim() || (data.apName || '').trim());
    }

    function formatUniFiName(data) {
        if (!data) return '—';
        const name = (data.unifiName || '').trim();
        return name || '—';
    }

    return {
        resolveEffectiveDeviceName,
        shouldDisplayUniFiCard,
        formatUniFiName
    };
});
