const test = require('node:test');
const assert = require('node:assert/strict');

const {
    escapeHtml,
    sanitizeHttpUrl,
    renderTokenRowHtml,
    renderLinkedChildRowHtml,
    renderParentDeviceOptionHtml,
    renderLiveProgressCardHtml,
    renderPresenceStreamItemHtml,
    renderTimelineEventItemHtml,
    renderDetailedHistoryEventHtml,
    renderPresenceTooltipHtml,
} = require('./html-utils.js');

test('escapeHtml escapes all HTML special characters safely', () => {
    assert.equal(escapeHtml(null), '');
    assert.equal(escapeHtml(undefined), '');
    assert.equal(escapeHtml(0), '0');
    assert.equal(
        escapeHtml(`<script>alert("xss" & 'evil')</script>`),
        '&lt;script&gt;alert(&quot;xss&quot; &amp; &#39;evil&#39;)&lt;/script&gt;'
    );
});

test('sanitizeHttpUrl allows http/https and rejects javascript/data schemes', () => {
    assert.equal(sanitizeHttpUrl('https://10.0.0.1:8443/admin'), 'https://10.0.0.1:8443/admin');
    assert.equal(sanitizeHttpUrl('http://nas.local/'), 'http://nas.local/');
    assert.equal(sanitizeHttpUrl('  https://example.com/a?b=1  '), 'https://example.com/a?b=1');
    assert.equal(sanitizeHttpUrl('javascript:alert(1)'), '');
    assert.equal(sanitizeHttpUrl('JAVASCRIPT:alert(1)'), '');
    assert.equal(sanitizeHttpUrl('data:text/html,<script>alert(1)</script>'), '');
    assert.equal(sanitizeHttpUrl('vbscript:msgbox(1)'), '');
    assert.equal(sanitizeHttpUrl(''), '');
    assert.equal(sanitizeHttpUrl(null), '');
});

test('renderTokenRowHtml escapes token name/prefix and avoids inline onclick', () => {
    const html = renderTokenRowHtml({
        id: 42,
        name: `prod's "key" <img src=x onerror=alert(1)>`,
        token_prefix: `lo_<script>`,
        createdDate: '11/18/2026',
        lastUsed: 'Never',
    });

    assert.doesNotMatch(html, /onclick=/i);
    assert.doesNotMatch(html, /<img|<script>/i);
    assert.match(html, /data-token-id="42"/);
    assert.match(html, /data-token-name="prod&#39;s &quot;key&quot; &lt;img src=x onerror=alert\(1\)&gt;"/);
    assert.match(html, /lo_&lt;script&gt;/);
});

test('renderLinkedChildRowHtml escapes child label and avoids inline onclick', () => {
    const html = renderLinkedChildRowHtml(
        `alias <img src=x onerror=alert(1)> (10.0.0.99)`,
        `10.0.0.1';alert(1);//`
    );

    assert.doesNotMatch(html, /onclick=/i);
    assert.doesNotMatch(html, /<img src=x/i);
    assert.match(html, /data-child-ip="10\.0\.0\.99"/);
    assert.match(html, /data-parent-ip="10\.0\.0\.1&#39;;alert\(1\);\/\/"/);
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
});

test('renderParentDeviceOptionHtml escapes device name and MAC attributes', () => {
    const html = renderParentDeviceOptionHtml({
        label: `Router" onclick="alert(1)`,
        mac: `aa:bb:cc:dd:ee:ff"><script>`,
    });

    assert.doesNotMatch(html, /<script>/i);
    assert.doesNotMatch(html, /" onclick="/);
    assert.match(html, /&quot; onclick=&quot;alert\(1\)/);
});

test('renderLiveProgressCardHtml escapes network names, hostname, IP, and errors', () => {
    const html = renderLiveProgressCardHtml({
        status: 'running',
        stage: 'sweep',
        percent: 50,
        remaining: 12,
        elapsed: 5,
        network_index: 1,
        network_count: 2,
        current_network_name: `<img src=x onerror=alert(1)>`,
        active_networks: [`Home`, `LAN<script>alert(1)</script>`],
        last_port_scan_host: {
            ip: `10.0.0.5<svg onload=alert(1)>`,
            hostname: `box"><script>alert(2)</script>`,
            error: `fail <img src=x onerror=alert(3)>`,
        },
    }, { formatSeconds: s => `${s}s` });

    assert.doesNotMatch(html, /<script>|<img|<svg/i);
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
    assert.match(html, /LAN&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.match(html, /box&quot;&gt;&lt;script&gt;alert\(2\)&lt;\/script&gt;/);
});

test('renderPresenceStreamItemHtml escapes event fields and avoids inline onclick', () => {
    const html = renderPresenceStreamItemHtml({
        ip: `10.0.0.8'"><script>`,
        hostname: `<b>evil</b>`,
        event: 'join',
        duration: 0,
    }, {
        dayTitle: 'Today',
        timeStr: '10:00 AM',
        relativeTime: 'just now',
        fullTimeStr: '11/18/2026, 10:00:00 AM',
        durPill: '',
    });

    assert.doesNotMatch(html, /onclick=/i);
    assert.doesNotMatch(html, /<b>|<script>/i);
    assert.match(html, /data-ip="10\.0\.0\.8&#39;&quot;&gt;&lt;script&gt;"/);
    assert.match(html, /&lt;b&gt;evil&lt;\/b&gt;/);
});

test('renderTimelineEventItemHtml and renderDetailedHistoryEventHtml escape network_name, event, ip, mac', () => {
    const evt = {
        event: `join<img src=x>`,
        network_name: `Guest <script>alert(1)</script>`,
        ip: `10.0.0.7<svg>`,
        mac: `aa:bb:cc:dd:ee:ff<b>`,
        duration: 30,
    };
    const itemHtml = renderTimelineEventItemHtml({
        ...evt,
        event: 'join',
    }, '1m ago', s => `${s}s`);
    assert.doesNotMatch(itemHtml, /<script>/i);
    assert.match(itemHtml, /Guest &lt;script&gt;alert\(1\)&lt;\/script&gt;/);

    const unknownEvtHtml = renderTimelineEventItemHtml(evt, '1m ago', s => `${s}s`);
    assert.doesNotMatch(unknownEvtHtml, /<img/i);
    assert.match(unknownEvtHtml, /join&lt;img src=x&gt;/);

    const detailHtml = renderDetailedHistoryEventHtml({
        ...evt,
        event: 'return',
        createdStr: '11/18/2026, 10:00:00 AM',
    }, '2m ago', s => `${s}s`);
    assert.doesNotMatch(detailHtml, /<script>|<svg>|<b>/i);
    assert.match(detailHtml, /Guest &lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.match(detailHtml, /10\.0\.0\.7&lt;svg&gt;/);
    assert.match(detailHtml, /AA:BB:CC:DD:EE:FF&lt;B&gt;/);
});

test('renderPresenceTooltipHtml escapes ip and networkName', () => {
    const html = renderPresenceTooltipHtml({
        isCurrent: true,
        start: new Date('2026-11-18T10:00:00Z'),
        end: new Date('2026-11-18T10:05:00Z'),
        ip: `10.0.0.5<script>`,
        networkName: `IoT <img src=x>`,
    }, '5m', d => d.toISOString(), { includeIP: true });

    assert.doesNotMatch(html, /<script>|<img/i);
    assert.match(html, /10\.0\.0\.5&lt;script&gt;/);
    assert.match(html, /IoT &lt;img src=x&gt;/);
});

test('renderTokenRowHtml and renderLinkedChildRowHtml neutralize onclick injection in all fields', () => {
    const tokenHtml = renderTokenRowHtml({
        id: `9" onclick="alert(1)`,
        name: `evil' onclick="alert(2)`,
        prefix: `lo_" onclick="alert(3)`,
        created_at: '2026-11-18T10:00:00Z',
        last_used_at: `" onclick="alert(4)`,
    }, s => s);
    assert.doesNotMatch(tokenHtml, /\sonclick="/i);

    const childHtml = renderLinkedChildRowHtml(
        `device" onclick="alert(5) (10.0.0.5)`,
        `10.0.0.1" onclick="alert(6)`
    );
    assert.doesNotMatch(childHtml, /\sonclick="/i);
});
