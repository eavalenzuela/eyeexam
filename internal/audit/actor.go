package audit

import (
	"context"
	"fmt"
	"os/user"
	"strconv"
)

// Actor identifies who initiated an audited action. OSUser/OSUID always
// reflect the process owner; AppUser is an optional human identity declared
// by the operator (CLI --actor-app, or schedule add --actor-app) so that
// runs invoked by a service account can still be attributed in the audit
// log to the human who authorized them.
type Actor struct {
	OSUser  string  `json:"os_user"`
	OSUID   int     `json:"os_uid"`
	AppUser *string `json:"app_user,omitempty"`
}

// ValidateAppUser checks an --actor-app value. The value flows into
// Actor.String() (which uses '/' as a separator) and into the audit chain,
// so we constrain it to a printable, separator-free identifier.
func ValidateAppUser(s string) error {
	if s == "" {
		return fmt.Errorf("audit: app_user must not be empty")
	}
	if len(s) > 64 {
		return fmt.Errorf("audit: app_user too long (max 64)")
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '-', r == '@', r == '+':
			// allowed
		default:
			return fmt.Errorf("audit: app_user %q contains disallowed rune %q (allowed: alnum . _ - @ +)", s, r)
		}
	}
	return nil
}

func (a Actor) String() string {
	if a.AppUser != nil {
		return fmt.Sprintf("%s/%s(uid=%d)", *a.AppUser, a.OSUser, a.OSUID)
	}
	return fmt.Sprintf("%s(uid=%d)", a.OSUser, a.OSUID)
}

// ActorFromOS resolves the current OS user. Falls back to the uid alone if
// the username lookup fails.
func ActorFromOS(_ context.Context) (Actor, error) {
	u, err := user.Current()
	if err != nil {
		return Actor{}, fmt.Errorf("audit: resolving current user: %w", err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		// non-numeric on some platforms (windows); record 0
		uid = 0
	}
	return Actor{OSUser: u.Username, OSUID: uid}, nil
}
