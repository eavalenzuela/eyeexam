package pack

// Refuser is the hard-refuse list. The mechanism is in place from M1; the
// concrete entries are populated in M4 once Atomic Red Team support arrives
// and we have real test ids to evaluate. Until then the list is empty.
type Refuser struct {
	entries map[string]string // id -> reason
}

func NewRefuser(entries map[string]string) *Refuser {
	if entries == nil {
		entries = builtinRefuseList()
	}
	return &Refuser{entries: entries}
}

func (r *Refuser) Refused(id string) bool {
	_, ok := r.entries[id]
	return ok
}

func (r *Refuser) Reason(id string) string {
	if r == nil {
		return ""
	}
	return r.entries[id]
}

func (r *Refuser) Entries() map[string]string {
	out := make(map[string]string, len(r.entries))
	for k, v := range r.entries {
		out[k] = v
	}
	return out
}

// builtinRefuseList is the curated list of test ids that eyeexam will never
// schedule. Empty in M1; populated in M4 (see IMPLEMENTATION.md §8).
func builtinRefuseList() map[string]string {
	return map[string]string{}
}
