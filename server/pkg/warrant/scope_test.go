package warrant

import "testing"

func TestIsSubset(t *testing.T) {
	tests := []struct {
		name   string
		parent []string
		child  []string
		want   bool
	}{
		{
			name:   "exact match",
			parent: []string{"gmail:send"},
			child:  []string{"gmail:send"},
			want:   true,
		},
		{
			name:   "wildcard action in parent",
			parent: []string{"gmail:*"},
			child:  []string{"gmail:send"},
			want:   true,
		},
		{
			name:   "wildcard resource in parent",
			parent: []string{"*:read"},
			child:  []string{"research:read"},
			want:   true,
		},
		{
			name:   "double wildcard covers everything",
			parent: []string{"*:*"},
			child:  []string{"research:read", "gmail:send", "database:delete"},
			want:   true,
		},
		{
			name:   "cross-resource fail",
			parent: []string{"gmail:send"},
			child:  []string{"database:send"},
			want:   false,
		},
		{
			name:   "cross-action fail",
			parent: []string{"gmail:send"},
			child:  []string{"gmail:delete"},
			want:   false,
		},
		{
			name:   "empty child is always subset",
			parent: []string{"gmail:send"},
			child:  []string{},
			want:   true,
		},
		{
			name:   "empty parent cannot cover non-empty child",
			parent: []string{},
			child:  []string{"gmail:send"},
			want:   false,
		},
		{
			name:   "mixed wildcards hit — partial wildcard covers specific",
			parent: []string{"gmail:*", "research:read"},
			child:  []string{"gmail:send", "gmail:read", "research:read"},
			want:   true,
		},
		{
			name:   "mixed wildcards miss — child exceeds parent",
			parent: []string{"gmail:*", "research:read"},
			child:  []string{"gmail:send", "database:delete"},
			want:   false,
		},
		{
			name:   "invalid entry in child treated as uncoverable",
			parent: []string{"*:*"},
			child:  []string{"notvalid"},
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsSubset(tc.parent, tc.child)
			if got != tc.want {
				t.Errorf("IsSubset(%v, %v) = %v, want %v", tc.parent, tc.child, got, tc.want)
			}
		})
	}
}

func TestParseScope(t *testing.T) {
	tests := []struct {
		input   string
		wantOK  bool
		wantRes string
		wantAct string
	}{
		{"gmail:send", true, "gmail", "send"},
		{"*:*", true, "*", "*"},
		{"research:read", true, "research", "read"},
		{"notvalid", false, "", ""},
		{":send", false, "", ""},
		{"gmail:", false, "", ""},
		{"", false, "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, ok := ParseScope(tc.input)
			if ok != tc.wantOK {
				t.Fatalf("ParseScope(%q) ok=%v, want %v", tc.input, ok, tc.wantOK)
			}
			if ok {
				if got.Resource != tc.wantRes || got.Action != tc.wantAct {
					t.Errorf("got {%s %s}, want {%s %s}", got.Resource, got.Action, tc.wantRes, tc.wantAct)
				}
			}
		})
	}
}

func TestEntryCovers(t *testing.T) {
	tests := []struct {
		parent ScopeEntry
		child  ScopeEntry
		want   bool
	}{
		{ScopeEntry{"gmail", "send"}, ScopeEntry{"gmail", "send"}, true},
		{ScopeEntry{"*", "send"}, ScopeEntry{"gmail", "send"}, true},
		{ScopeEntry{"gmail", "*"}, ScopeEntry{"gmail", "send"}, true},
		{ScopeEntry{"*", "*"}, ScopeEntry{"anything", "goes"}, true},
		{ScopeEntry{"gmail", "send"}, ScopeEntry{"gmail", "delete"}, false},
		{ScopeEntry{"gmail", "send"}, ScopeEntry{"database", "send"}, false},
	}

	for _, tc := range tests {
		got := EntryCovers(tc.parent, tc.child)
		if got != tc.want {
			t.Errorf("EntryCovers(%v, %v) = %v, want %v", tc.parent, tc.child, got, tc.want)
		}
	}
}
