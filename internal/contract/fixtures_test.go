package contract_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	ipv4Pattern = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	macPattern  = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b`)
)

func TestFixturesRemainAnonymized(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")
	testNetwork := netip.MustParsePrefix("192.0.2.0/24")
	forbidden := []string{"192.168.", "10.0.", "172.16.", "site-router.example"}

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(data)
		for _, value := range ipv4Pattern.FindAllString(text, -1) {
			address, err := netip.ParseAddr(value)
			if err != nil || !testNetwork.Contains(address) {
				t.Errorf("%s contains a non-TEST-NET-1 IPv4 address", path)
			}
		}
		for _, value := range macPattern.FindAllString(text, -1) {
			if !strings.HasPrefix(strings.ToLower(value), "02:00:00:00:") {
				t.Errorf("%s contains a non-synthetic MAC address", path)
			}
		}
		lower := strings.ToLower(text)
		for _, value := range forbidden {
			if strings.Contains(lower, value) {
				t.Errorf("%s contains forbidden site-specific data", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan fixture tree: %v", err)
	}
}
