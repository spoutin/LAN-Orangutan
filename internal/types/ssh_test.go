package types

import "testing"

func TestDeviceEffectiveSSHRespectsManualStates(t *testing.T) {
	tests := []struct {
		name     string
		device   Device
		wantPort int
		wantSet  bool
	}{
		{"auto uses detected SSH", Device{DetectedSSHPort: 2222}, 2222, true},
		{"manual available replaces detected SSH", Device{DetectedSSHPort: 2222, SSHOverride: SSHOverrideAvailable, SSHOverridePort: 2200}, 2200, true},
		{"manual unavailable hides detected SSH", Device{DetectedSSHPort: 22, SSHOverride: SSHOverrideUnavailable}, 0, false},
		{"auto without detection has no SSH", Device{}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPort, gotSet := tt.device.EffectiveSSH()
			if gotPort != tt.wantPort || gotSet != tt.wantSet {
				t.Errorf("EffectiveSSH() = (%d, %t), want (%d, %t)", gotPort, gotSet, tt.wantPort, tt.wantSet)
			}
		})
	}
}
