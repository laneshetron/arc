// Package profiling wires optional CPU and heap profiles into the commands.
package profiling

import (
	"flag"
	"os"
	"runtime"
	"runtime/pprof"
)

// Flags registers -cpuprofile and -memprofile on fs. Call Start after
// parsing; the returned function writes the profiles and must run before
// the process exits.
type Flags struct {
	cpu, mem *string
}

func Register(fs *flag.FlagSet) *Flags {
	return &Flags{
		cpu: fs.String("cpuprofile", "", "write a CPU profile to this file on exit"),
		mem: fs.String("memprofile", "", "write an allocation profile to this file on exit"),
	}
}

func (f *Flags) Start() (stop func(), err error) {
	var cpuFile *os.File
	if *f.cpu != "" {
		if cpuFile, err = os.Create(*f.cpu); err != nil {
			return nil, err
		}
		if err = pprof.StartCPUProfile(cpuFile); err != nil {
			cpuFile.Close()
			return nil, err
		}
	}
	return func() {
		if cpuFile != nil {
			pprof.StopCPUProfile()
			cpuFile.Close()
		}
		if *f.mem != "" {
			if mf, err := os.Create(*f.mem); err == nil {
				runtime.GC()
				pprof.Lookup("allocs").WriteTo(mf, 0)
				mf.Close()
			}
		}
	}, nil
}
