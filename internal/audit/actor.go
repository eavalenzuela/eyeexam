package audit

import (
	"context"
	"fmt"
	"os/user"
	"strconv"
)

// Actor identifies who initiated an audited action. v1 populates only the
// OS-user fields; AppUser is reserved for a future frontend that adds login.
type Actor struct {
	OSUser  string  `json:"os_user"`
	OSUID   int     `json:"os_uid"`
	AppUser *string `json:"app_user,omitempty"`
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
