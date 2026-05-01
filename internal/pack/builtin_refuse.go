package pack

// Refuser is the hard-refuse list. Mechanism landed in M1; the curated
// entries below were populated alongside M4 (Atomic Red Team support). See
// builtinRefuseList for the categories and rationale.
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
// schedule. Categories per PLAN.md §"Safety rails":
//
//   - Domain-controller modification — eyeexam is BAS, not red-team
//     emulation; "DCSync" / "Golden Ticket" / "Skeleton Key" type tests
//     leave persistent backdoors a homelab/SOC isn't equipped to clean up.
//   - EDR-disable — disabling the very thing under test is incoherent for
//     scoring purposes and risks leaving the host unprotected if the run
//     crashes mid-flight.
//   - Bootloader / firmware modification — recovery requires physical
//     access; outside the BAS guarantee that hosts return to their prior
//     state via verify_cleanup.
//
// Operators can extend this list by editing this file in their fork. A
// future milestone may move the list into config so it is operator-owned;
// for v1 the curated set is in code so eyeexam ships with safe defaults.
//
// Atomic Red Team test ids in this list use eyeexam's id scheme
// (atomic-<technique>-<index>) — the index is 1-based and matches the
// position of the atomic_test in the upstream YAML at the pinned revision.
// If upstream re-orders within a technique file, ids may shift; the
// docs/atomic-redteam.md note covers operator workflow for that case.
func builtinRefuseList() map[string]string {
	const (
		dcModify   = "domain-controller modification: persistent backdoor outside BAS scope"
		edrDisable = "EDR-disable: incoherent for scoring; can leave host unprotected"
		bootloader = "bootloader / firmware modification: recovery requires physical access"
	)
	return map[string]string{
		// Persistence on Domain Controller (Skeleton Key)
		"atomic-T1556.001-1": dcModify,
		"atomic-T1556.001-2": dcModify,
		// DCSync (Credentials from password stores)
		"atomic-T1003.006-1": dcModify,
		"atomic-T1003.006-2": dcModify,
		// Golden / Silver / Diamond ticket
		"atomic-T1558.001-1": dcModify,
		"atomic-T1558.002-1": dcModify,
		"atomic-T1558.003-1": dcModify,
		"atomic-T1558.004-1": dcModify,

		// Impair Defenses: Disable / modify tools
		"atomic-T1562.001-1": edrDisable,
		"atomic-T1562.001-2": edrDisable,
		"atomic-T1562.001-3": edrDisable,
		"atomic-T1562.001-4": edrDisable,
		"atomic-T1562.001-5": edrDisable,
		"atomic-T1562.001-6": edrDisable,
		// Impair Defenses: Disable Windows Event Logging
		"atomic-T1562.002-1": edrDisable,
		// Impair Defenses: Disable or Modify System Firewall (when used to
		// blackhole the EDR / SIEM)
		"atomic-T1562.004-1": edrDisable,

		// Bootkit
		"atomic-T1542.003-1": bootloader,
		// Pre-OS Boot: System Firmware
		"atomic-T1542.001-1": bootloader,
	}
}
