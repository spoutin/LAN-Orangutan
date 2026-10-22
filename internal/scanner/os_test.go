package scanner

import (
	"testing"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

func TestInferOS_LinuxWithUbuntuBanner(t *testing.T) {
	osMatches := []nmapOSMatch{
		{Name: "Linux 5.4 - 5.15", Accuracy: 95, Classes: []nmapOSClass{{OSFamily: "Linux", Vendor: "Linux", OSGen: "5.X"}}},
	}
	services := []types.OpenService{
		{Port: 22, Name: "ssh", Version: "OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 Ubuntu Linux; protocol 2.0"},
	}

	name, version, family := InferOS(osMatches, services)
	if family != "Linux" {
		t.Errorf("family = %q, want Linux", family)
	}
	if name != "Ubuntu Linux" {
		t.Errorf("name = %q, want Ubuntu Linux", name)
	}
	if version != "22.04" {
		t.Errorf("version = %q, want 22.04", version)
	}
}

func TestInferOS_WindowsStackMatch(t *testing.T) {
	osMatches := []nmapOSMatch{
		{Name: "Microsoft Windows 11", Accuracy: 96, Classes: []nmapOSClass{{OSFamily: "Windows", Vendor: "Microsoft", OSGen: "11"}}},
	}
	name, version, family := InferOS(osMatches, nil)
	if family != "Windows" || name != "Windows 11" || version != "11" {
		t.Errorf("got %s / %s / %s, want Windows 11 / 11 / Windows", name, version, family)
	}
}

func TestInferOS_HardenedEmptyHost(t *testing.T) {
	name, version, family := InferOS(nil, nil)
	if name != "" || version != "" || family != "" {
		t.Errorf("got %q / %q / %q, want empty strings", name, version, family)
	}
}

func TestInferOS_AppleMacOSMatch(t *testing.T) {
	osMatches := []nmapOSMatch{
		{Name: "Apple macOS 14 (Sonoma)", Accuracy: 90, Classes: []nmapOSClass{{OSFamily: "macOS", Vendor: "Apple", OSGen: "14.X"}}},
	}
	name, version, family := InferOS(osMatches, nil)
	if family != "Apple" || name != "Apple macOS 14 (Sonoma)" || version != "14" {
		t.Errorf("got %s / %s / %s, want Apple macOS 14 (Sonoma) / 14 / Apple", name, version, family)
	}
}

func TestInferOS_BSDMatch(t *testing.T) {
	osMatches := []nmapOSMatch{
		{Name: "FreeBSD 13.2-RELEASE", Accuracy: 92, Classes: []nmapOSClass{{OSFamily: "FreeBSD", Vendor: "FreeBSD", OSGen: "13.X"}}},
	}
	name, version, family := InferOS(osMatches, nil)
	if family != "BSD" || name != "FreeBSD 13.2-RELEASE" || version != "13.2" {
		t.Errorf("got %s / %s / %s, want FreeBSD 13.2-RELEASE / 13.2 / BSD", name, version, family)
	}
}

func TestInferOS_UnprivilegedServiceBannerOnly(t *testing.T) {
	// No stack matches (e.g. unprivileged scan without -O)
	services := []types.OpenService{
		{Port: 22, Name: "ssh", Version: "OpenSSH 9.2p1 Debian 2+deb12u2 (Debian Linux; protocol 2.0)"},
	}
	name, version, family := InferOS(nil, services)
	if family != "Linux" || name != "Debian Linux" || version != "12" {
		t.Errorf("got %s / %s / %s, want Debian Linux / 12 / Linux", name, version, family)
	}
}
