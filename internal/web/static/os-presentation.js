(function (root, factory) {
    const presentation = factory();
    if (typeof module === 'object' && module.exports) module.exports = presentation;
    root.formatOSDisplay = presentation.formatOSDisplay;
    root.getOSFamilyIcon = presentation.getOSFamilyIcon;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    const osIcons = {
        'linux': '<svg class="os-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2a5 5 0 0 0-5 5v5a5 5 0 0 0 10 0V7a5 5 0 0 0-5-5z"/><path d="M7 16a4 4 0 0 0-4 4v1h18v-1a4 4 0 0 0-4-4"/><circle cx="10" cy="7" r="1"/><circle cx="14" cy="7" r="1"/></svg>',
        'windows': '<svg class="os-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="8" height="8" x="3" y="3" rx="1"/><rect width="8" height="8" x="13" y="3" rx="1"/><rect width="8" height="8" x="3" y="13" rx="1"/><rect width="8" height="8" x="13" y="13" rx="1"/></svg>',
        'apple': '<svg class="os-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20.94c1.5 0 2.75-1.06 4-1.06 1.22 0 2.31 1.06 3.81 1.06 1.63 0 3.19-1.47 4.19-3.03-2.19-1.25-2.5-4.47-.28-5.94-1.16-1.78-3.09-2.03-3.72-2.03-1.56 0-2.84 1-3.69 1-.84 0-2.19-1-3.53-1-2.31 0-4.66 1.78-4.66 5.34 0 3.38 2.22 7.66 3.88 7.66z"/><path d="M12 5.5c.88-1.09 1.44-2.59 1.28-4.09-1.25.06-2.81.84-3.69 1.88-.78.91-1.47 2.44-1.28 3.91 1.41.12 2.81-.66 3.69-1.7z"/></svg>',
        'darwin': '<svg class="os-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20.94c1.5 0 2.75-1.06 4-1.06 1.22 0 2.31 1.06 3.81 1.06 1.63 0 3.19-1.47 4.19-3.03-2.19-1.25-2.5-4.47-.28-5.94-1.16-1.78-3.09-2.03-3.72-2.03-1.56 0-2.84 1-3.69 1-.84 0-2.19-1-3.53-1-2.31 0-4.66 1.78-4.66 5.34 0 3.38 2.22 7.66 3.88 7.66z"/><path d="M12 5.5c.88-1.09 1.44-2.59 1.28-4.09-1.25.06-2.81.84-3.69 1.88-.78.91-1.47 2.44-1.28 3.91 1.41.12 2.81-.66 3.69-1.7z"/></svg>',
        'android': '<svg class="os-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 16v-6a7 7 0 0 1 14 0v6"/><line x1="8" x2="8" y1="3" y2="6"/><line x1="16" x2="16" y1="3" y2="6"/><circle cx="9" cy="11" r="1"/><circle cx="15" cy="11" r="1"/><rect width="14" height="6" x="5" y="16" rx="2"/></svg>',
        'bsd': '<svg class="os-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2v20M8 5v6a4 4 0 0 0 8 0V5M5 2l3 3M19 2l-3 3M10 22h4"/></svg>'
    };

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function getOSFamilyIcon(familyOrName) {
        if (!familyOrName) return null;
        const s = familyOrName.toLowerCase();
        if (s.includes('android')) return osIcons['android'];
        if (s.includes('linux') || s.includes('ubuntu') || s.includes('debian') || s.includes('alpine') || s.includes('fedora') || s.includes('centos') || s.includes('arch')) return osIcons['linux'];
        if (s.includes('windows')) return osIcons['windows'];
        if (s.includes('apple') || s.includes('macos') || s.includes('darwin') || s.includes('ios') || s.includes('mac os')) return osIcons['apple'];
        if (s.includes('bsd') || s.includes('freebsd') || s.includes('openbsd') || s.includes('netbsd')) return osIcons['bsd'];
        return null;
    }

    function formatOSDisplay(dev) {
        if (!dev) return { html: '—', text: '—', icon: '' };
        const custom = (dev.custom_os || dev.customOS || '').trim();
        const os = (dev.os || '').trim();
        const ver = (dev.os_version || dev.osVersion || '').trim();
        const family = (dev.os_family || dev.osFamily || '').trim();

        if (custom) {
            const iconSvg = getOSFamilyIcon(family) || getOSFamilyIcon(custom);
            if (iconSvg) {
                return {
                    html: `${iconSvg} <span>${escapeHtml(custom)}</span>`,
                    text: custom,
                    icon: iconSvg
                };
            }
            return { html: escapeHtml(custom), text: custom, icon: '' };
        }

        if (!os && !ver) {
            return { html: '—', text: '—', icon: '' };
        }

        let fullText = os;
        if (family === 'Linux') {
            fullText = fullText.replace(/\s+Linux$/i, '');
        }
        if (ver && !fullText.includes(ver)) {
            fullText = fullText ? `${fullText} ${ver}` : ver;
        }

        const iconSvg = getOSFamilyIcon(family) || getOSFamilyIcon(os);
        if (iconSvg) {
            return {
                html: `${iconSvg} <span>${escapeHtml(fullText)}</span>`,
                text: fullText,
                icon: iconSvg
            };
        }
        return { html: escapeHtml(fullText), text: fullText, icon: '' };
    }

    return { formatOSDisplay, getOSFamilyIcon };
});
