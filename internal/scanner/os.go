package scanner

import (
	"regexp"
	"strings"

	"github.com/spoutin/LAN-Orangutan/internal/types"
)

type nmapOS struct {
	Matches []nmapOSMatch `xml:"osmatch"`
}

type nmapOSMatch struct {
	Name     string        `xml:"name,attr"`
	Accuracy int           `xml:"accuracy,attr"`
	Classes  []nmapOSClass `xml:"osclass"`
}

type nmapOSClass struct {
	Type     string `xml:"type,attr"`
	Vendor   string `xml:"vendor,attr"`
	OSFamily string `xml:"osfamily,attr"`
	OSGen    string `xml:"osgen,attr"`
	Accuracy int    `xml:"accuracy,attr"`
}

var (
	reUbuntuVer    = regexp.MustCompile(`(?i)ubuntu[^\d]*(\d{2}\.\d{2})`)
	reDebianDeb    = regexp.MustCompile(`(?i)deb(\d+)`)
	reDebianVer    = regexp.MustCompile(`(?i)(?:debian\s+)(\d+)`)
	reAlpineVer    = regexp.MustCompile(`(?i)alpine[^\d]*(\d+\.\d+)`)
	reFedoraVer    = regexp.MustCompile(`(?i)(?:fc|fedora\s+)(\d+)`)
	reRHELVer      = regexp.MustCompile(`(?i)(?:el|rhel\s+|centos\s+)(\d+)`)
	reWindowsVer   = regexp.MustCompile(`(?i)windows\s+(11|10|8\.1|8|7|server\s+\d{4}|20\d{2})`)
	reAppleVer     = regexp.MustCompile(`(?i)(?:macos|mac os x|ios)\s+(\d+(?:\.\d+)?)`)
	reBSDVer       = regexp.MustCompile(`(?i)(?:freebsd|openbsd|netbsd)\s+(\d+(?:\.\d+)?)`)
	reGenericVer   = regexp.MustCompile(`\b(\d+(?:\.\d+)+)\b`)
)

// canonicalFamily maps raw family/vendor strings to standard UI categories.
func canonicalFamily(raw string) string {
	s := strings.ToLower(raw)
	switch {
	case strings.Contains(s, "android"):
		return "Android"
	case strings.Contains(s, "linux"):
		return "Linux"
	case strings.Contains(s, "windows"):
		return "Windows"
	case strings.Contains(s, "apple"), strings.Contains(s, "macos"), strings.Contains(s, "mac os"), strings.Contains(s, "darwin"), strings.Contains(s, "ios"):
		return "Apple"
	case strings.Contains(s, "bsd"):
		return "BSD"
	default:
		return ""
	}
}

// inferFromServices inspects banners for operating system and distribution hints.
func inferFromServices(services []types.OpenService) (distroName, distroVersion, family string) {
	for _, s := range services {
		text := s.Name + " " + s.Version
		lower := strings.ToLower(text)

		// 1. Ubuntu
		if strings.Contains(lower, "ubuntu") {
			distroName = "Ubuntu Linux"
			family = "Linux"
			if m := reUbuntuVer.FindStringSubmatch(text); len(m) > 1 {
				distroVersion = m[1]
			} else {
				// Infer from well-known OpenSSH package versions on Ubuntu
				switch {
				case strings.Contains(lower, "9.6p1"):
					distroVersion = "24.04"
				case strings.Contains(lower, "8.9p1"):
					distroVersion = "22.04"
				case strings.Contains(lower, "8.2p1"):
					distroVersion = "20.04"
				case strings.Contains(lower, "7.6p1"):
					distroVersion = "18.04"
				case strings.Contains(lower, "7.2p2"):
					distroVersion = "16.04"
				}
			}
			return
		}

		// 2. Debian
		if strings.Contains(lower, "debian") {
			distroName = "Debian Linux"
			family = "Linux"
			if m := reDebianDeb.FindStringSubmatch(text); len(m) > 1 {
				distroVersion = m[1]
			} else if m := reDebianVer.FindStringSubmatch(text); len(m) > 1 {
				distroVersion = m[1]
			}
			return
		}

		// 3. Alpine
		if strings.Contains(lower, "alpine") {
			distroName = "Alpine Linux"
			family = "Linux"
			if m := reAlpineVer.FindStringSubmatch(text); len(m) > 1 {
				distroVersion = m[1]
			}
			return
		}

		// 4. Fedora
		if strings.Contains(lower, "fedora") {
			distroName = "Fedora Linux"
			family = "Linux"
			if m := reFedoraVer.FindStringSubmatch(text); len(m) > 1 {
				distroVersion = m[1]
			}
			return
		}

		// 5. RHEL / CentOS
		if strings.Contains(lower, "centos") || strings.Contains(lower, "red hat") || strings.Contains(lower, "rhel") {
			distroName = "RHEL/CentOS"
			family = "Linux"
			if m := reRHELVer.FindStringSubmatch(text); len(m) > 1 {
				distroVersion = m[1]
			}
			return
		}

		// 6. Windows
		if strings.Contains(lower, "windows") || strings.Contains(lower, "microsoft") {
			distroName = "Windows"
			family = "Windows"
			if m := reWindowsVer.FindStringSubmatch(text); len(m) > 1 {
				distroVersion = m[1]
				distroName = "Windows " + m[1]
			}
			return
		}

		// 7. FreeBSD / OpenBSD
		if strings.Contains(lower, "freebsd") {
			distroName = "FreeBSD"
			family = "BSD"
			if m := reBSDVer.FindStringSubmatch(text); len(m) > 1 {
				distroVersion = m[1]
			}
			return
		}
	}
	return "", "", ""
}

// InferOS combines Nmap OS stack matches with service banner heuristics to determine
// the target's operating system, version, and family.
func InferOS(osMatches []nmapOSMatch, services []types.OpenService) (osName, osVersion, osFamily string) {
	// First check service banners for specific distribution details
	sDistro, sVer, sFamily := inferFromServices(services)

	// If no stack matches were found, use service banner results
	if len(osMatches) == 0 {
		return sDistro, sVer, sFamily
	}

	// Pick the highest accuracy OS match
	topMatch := osMatches[0]
	for _, m := range osMatches {
		if m.Accuracy > topMatch.Accuracy {
			topMatch = m
		}
	}

	matchFamily := ""
	matchGen := ""
	for _, c := range topMatch.Classes {
		if fam := canonicalFamily(c.OSFamily); fam != "" {
			matchFamily = fam
			matchGen = c.OSGen
			break
		}
		if fam := canonicalFamily(c.Vendor); fam != "" {
			matchFamily = fam
			matchGen = c.OSGen
			break
		}
	}
	if matchFamily == "" {
		matchFamily = canonicalFamily(topMatch.Name)
	}

	// If service banners identified a specific Linux distribution and stack match is Linux,
	// refine with the distribution name and version
	if sFamily == "Linux" && (matchFamily == "Linux" || matchFamily == "") {
		osName = sDistro
		osVersion = sVer
		osFamily = "Linux"
		return osName, osVersion, osFamily
	}

	osName = topMatch.Name
	osFamily = matchFamily

	// Clean up names
	if strings.HasPrefix(osName, "Microsoft Windows") {
		osName = strings.TrimPrefix(osName, "Microsoft ")
	}

	// Determine version
	if sVer != "" && sFamily == osFamily {
		osVersion = sVer
	} else if m := reBSDVer.FindStringSubmatch(topMatch.Name); len(m) > 1 {
		osVersion = m[1]
	} else if m := reWindowsVer.FindStringSubmatch(topMatch.Name); len(m) > 1 {
		osVersion = m[1]
	} else if m := reAppleVer.FindStringSubmatch(topMatch.Name); len(m) > 1 {
		osVersion = m[1]
	} else if matchGen != "" {
		osVersion = strings.TrimSuffix(matchGen, ".X")
	} else if m := reGenericVer.FindStringSubmatch(topMatch.Name); len(m) > 1 {
		osVersion = m[1]
	}

	return osName, osVersion, osFamily
}
