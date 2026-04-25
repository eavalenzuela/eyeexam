package detector

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

func TestFakeReturnsScript(t *testing.T) {
	f := NewFake("fake")
	f.On("abc-123", FakeScript{Hits: []Hit{MakeHit("h1", time.Now(), "web-01", map[string]string{"rule": "abc-123"})}})
	hits, err := f.Query(context.Background(), ExpectationQuery{
		Expectation: pack.Expectation{SigmaID: "abc-123"},
	})
	if err != nil || len(hits) != 1 {
		t.Fatalf("hits=%v err=%v", hits, err)
	}
	if len(f.Calls()) != 1 {
		t.Fatal("call not recorded")
	}
}

func TestFakeReturnsError(t *testing.T) {
	f := NewFake("fake")
	f.On("abc-123", FakeScript{Err: errors.New("boom")})
	_, err := f.Query(context.Background(), ExpectationQuery{
		Expectation: pack.Expectation{SigmaID: "abc-123"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFakeUnscriptedReturnsZeroHits(t *testing.T) {
	f := NewFake("fake")
	hits, err := f.Query(context.Background(), ExpectationQuery{
		Expectation: pack.Expectation{SigmaID: "missing"},
	})
	if err != nil || len(hits) != 0 {
		t.Fatalf("hits=%v err=%v", hits, err)
	}
}
