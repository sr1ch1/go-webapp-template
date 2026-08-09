package auth

import "testing"

func TestIsValidTeamDomain(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"simple", "example", true},
		{"subdomain", "team.example", true},
		{"with suffix", "example.cloudflareaccess.com", true},
		{"empty", "", false},
		{"leading dot", ".example", false},
		{"trailing dot", "example.", false},
		{"leading hyphen", "-example", false},
		{"trailing hyphen", "example-", false},
		{"double dot", "example..com", false},
		{"slash", "example/foo", false},
		{"at sign", "example@evil", false},
		{"colon", "example:443", false},
		{"space", "example com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidTeamDomain(tc.in); got != tc.want {
				t.Errorf("isValidTeamDomain(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
