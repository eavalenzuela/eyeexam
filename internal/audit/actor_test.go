package audit

import "testing"

func TestValidateAppUser(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"alice", false},
		{"alice.smith", false},
		{"alice_smith", false},
		{"alice-smith", false},
		{"alice@example.com", false},
		{"alice+ops", false},
		{"a", false},
		{"A1.b_c-d@e", false},

		{"", true},
		{"alice/bob", true},        // separator, breaks Actor.String()
		{"alice bob", true},        // whitespace
		{"alice\tbob", true},       // tab
		{"alice\nbob", true},       // newline
		{"alice\x00bob", true},     // NUL
		{"alice!bob", true},        // disallowed punctuation
		{"αlice", true},            // non-ascii
		{stringOf("a", 65), true},  // too long
		{stringOf("a", 64), false}, // exactly at the cap
	}
	for _, tc := range cases {
		err := ValidateAppUser(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ValidateAppUser(%q) err=%v wantErr=%v", tc.in, err, tc.wantErr)
		}
	}
}

func TestActorStringWithAppUser(t *testing.T) {
	app := "alice"
	a := Actor{OSUser: "svc", OSUID: 1234, AppUser: &app}
	got := a.String()
	want := "alice/svc(uid=1234)"
	if got != want {
		t.Errorf("Actor.String() = %q, want %q", got, want)
	}

	a2 := Actor{OSUser: "svc", OSUID: 1234}
	if got := a2.String(); got != "svc(uid=1234)" {
		t.Errorf("Actor.String() without app = %q", got)
	}
}

func stringOf(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
