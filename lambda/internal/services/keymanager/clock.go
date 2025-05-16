package keymanager

import "time"

type Clock interface {
	Now() time.Time
}

type FakeClock struct {
	currentTime time.Time
}

func MockClock(currentTime time.Time) *FakeClock {
	return &FakeClock{currentTime: currentTime}
}
func (f *FakeClock) Now() time.Time {
	return f.currentTime
}

func (f *FakeClock) Add(duration time.Duration) {
	f.currentTime = f.currentTime.Add(duration)
}
func (f *FakeClock) SetTime(current time.Time) {
	f.currentTime = current
}
func ReealClock() Clock {
	return &RealClock{}
}

type RealClock struct{}

func (c *RealClock) Now() time.Time {
	return time.Now()
}
