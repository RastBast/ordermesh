package pii

import "testing"

func TestMaskEmail(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"alice@example.com": "a***@***.com",
		"bob@sub.domain.io": "b***@***.io",
		"invalid":           "***",
		"@example.com":      "***",
	}
	for in, want := range cases {
		if got := MaskEmail(in); got != want {
			t.Errorf("MaskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskPhone(t *testing.T) {
	t.Parallel()
	if got := MaskPhone("+1 415 555 1234"); got != "***34" {
		t.Errorf("got %q", got)
	}
	if got := MaskPhone("1"); got != "***" {
		t.Errorf("got %q", got)
	}
}

func TestMaskName(t *testing.T) {
	t.Parallel()
	if got := MaskName("Ada Lovelace"); got != "A. L." {
		t.Errorf("got %q", got)
	}
	if got := MaskName(""); got != "***" {
		t.Errorf("got %q", got)
	}
}

func TestMaskPAN(t *testing.T) {
	t.Parallel()
	if got := MaskPAN("4111 1111 1111 1111"); got != "**** 1111" {
		t.Errorf("got %q", got)
	}
}

func TestScrub(t *testing.T) {
	t.Parallel()
	in := "payment with card 4111 1111 1111 1111 from +1 415 555 1234"
	got := Scrub(in)
	if got == in {
		t.Fatalf("nothing scrubbed: %q", got)
	}
	if want := "[REDACTED_CARD]"; !contains(got, want) {
		t.Errorf("card not redacted: %q", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
