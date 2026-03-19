package warrant

import (
	"strings"
)

// ScopeEntry is a parsed "resource:action" permission pair.
type ScopeEntry struct {
	Resource string
	Action   string
}

// ParseScope parses a "resource:action" string.
// Returns (entry, true) on success, (zero, false) if the format is invalid.
func ParseScope(s string) (ScopeEntry, bool) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ScopeEntry{}, false
	}
	return ScopeEntry{Resource: parts[0], Action: parts[1]}, true
}

// EntryCovers reports whether parent covers child.
// A wildcard ("*") in either position matches any value.
func EntryCovers(parent, child ScopeEntry) bool {
	resourceOK := parent.Resource == "*" || parent.Resource == child.Resource
	actionOK := parent.Action == "*" || parent.Action == child.Action
	return resourceOK && actionOK
}

// IsSubset reports whether every entry in child is covered by at least one
// entry in parent. Invalid entries in child are treated as uncoverable.
func IsSubset(parent, child []string) bool {
	for _, ce := range child {
		childEntry, ok := ParseScope(ce)
		if !ok {
			return false
		}
		covered := false
		for _, pe := range parent {
			parentEntry, ok := ParseScope(pe)
			if !ok {
				continue
			}
			if EntryCovers(parentEntry, childEntry) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// NormaliseScope deduplicates scope entries and sorts them for stable output.
func NormaliseScope(scope []string) []string {
	seen := make(map[string]struct{}, len(scope))
	out := make([]string, 0, len(scope))
	for _, s := range scope {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	// Insertion-order dedup (deterministic enough for token claims).
	return out
}
