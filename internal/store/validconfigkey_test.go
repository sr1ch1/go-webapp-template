package store

import "testing"

func TestValidConfigKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"site_name", true},
		{"motd", true},
		{"a", true},
		{"ABC-123_xYz", true},
		{"-leading-dash", true},
		{"trailing-dash-", true},
		{"__only_underscores__", true},
		{"0", true},

		{"", false},
		{"with space", false},
		{"with.dot", false},
		{"with/slash", false},
		{"with:colon", false},
		{"with=equals", false},
		{"with?query", false},
		{"with'quote", false},
		{"with\"dquote", false},
		{"with\nnewline", false},
		{"unicode-ü", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := ValidConfigKey(tt.key); got != tt.want {
				t.Errorf("ValidConfigKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}
