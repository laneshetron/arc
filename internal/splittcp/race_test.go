//go:build race

package splittcp

// raceEnabled shortens transfers through gVisor's stack, which is very slow
// under the race detector.
const raceEnabled = true
