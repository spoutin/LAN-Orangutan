const test = require('node:test');
const assert = require('node:assert/strict');
const { switchConnectionPresentation } = require('./switch-presentation.js');

test('switch connection presentation hides when no port is available', () => {
    assert.deepEqual(switchConnectionPresentation({}), { visible: false });
});

test('switch connection presentation shows an active physical port', () => {
    assert.deepEqual(switchConnectionPresentation({ switchPort: 'gi1/23' }), {
        visible: true,
        title: 'Switch Connection',
        connectionText: 'gi1/23',
        interfaceLabel: 'Port:',
        showVLAN: true,
        showLink: true,
        showPoE: false
    });
});

test('switch connection presentation shows PoE only when supplied', () => {
    assert.equal(switchConnectionPresentation({ switchPort: 'gi1/23' }).showPoE, false);
    assert.equal(switchConnectionPresentation({ switchPort: 'gi1/23', switchPoeWatts: '8.2' }).showPoE, true);
});

test('switch connection presentation identifies port channels as uplinks', () => {
    assert.deepEqual(switchConnectionPresentation({ switchPort: 'Po2' }), {
        visible: true,
        title: 'Switch Uplink',
        connectionText: 'Po2',
        interfaceLabel: 'Interface:',
        showVLAN: false,
        showLink: false,
        showPoE: false
    });
});

test('switch connection presentation identifies SSID devices as upstream AP connections', () => {
    assert.deepEqual(switchConnectionPresentation({ switchPort: 'gi1/23', ssid: 'Home-IoT' }), {
        visible: true,
        title: 'Upstream AP Connection',
        connectionText: 'gi1/23',
        interfaceLabel: 'AP Port:',
        showVLAN: true,
        showLink: true,
        showPoE: false
    });
});
