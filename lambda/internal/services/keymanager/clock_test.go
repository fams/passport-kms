package keymanager

import (
	"testing"
	"time"
)

func TestFakeClock(t *testing.T) {
	fc := MockClock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	if !fc.Now().Equal(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("Now() incorreto")
	}
	fc.Add(2 * time.Hour)
	if !fc.Now().Equal(time.Date(2024, 1, 1, 2, 0, 0, 0, time.UTC)) {
		t.Error("Add() não atualizou corretamente")
	}
	fc.SetTime(time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC))
	if !fc.Now().Equal(time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("SetTime() não atualizou corretamente")
	}
}

func TestRealClock(t *testing.T) {
	rc := ReealClock()
	if time.Since(rc.Now()) > time.Second {
		t.Error("RealClock deve retornar o tempo atual")
	}
}
