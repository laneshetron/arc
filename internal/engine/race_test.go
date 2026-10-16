//go:build race

package engine

// raceEnabled shortens transfers through gVisor's stack, which is very slow
// under the race detector.
const raceEnabled = true
