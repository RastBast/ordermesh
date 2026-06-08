package ratelimit

import "testing"

func TestLocal_AllowsBurstThenBlocks(t *testing.T) {
	t.Parallel()
	l := NewLocal(1, 3) // 1 rps, burst 3
	defer l.Close()

	allowed := 0
	for i := 0; i < 5; i++ {
		if l.Allow("client-1") {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("want 3 allowed in burst, got %d", allowed)
	}
}

func TestLocal_KeysAreIndependent(t *testing.T) {
	t.Parallel()
	l := NewLocal(1, 1)
	defer l.Close()

	if !l.Allow("a") {
		t.Fatal("first request for a should pass")
	}
	if !l.Allow("b") {
		t.Fatal("first request for b should pass (independent bucket)")
	}
	if l.Allow("a") {
		t.Fatal("second request for a should be blocked")
	}
}
