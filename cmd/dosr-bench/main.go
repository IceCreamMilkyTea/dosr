// Command dosr-bench runs the evaluation experiments.
//
//	dosr-bench -exp all|verify|consensus|bundle|e2e|e2e_size|propagation|contention|faults|grinding [-quick] [-out eval/results/raw]
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/dosr/dosr/pkg/bench"
)

func main() {
	exp := flag.String("exp", "all", "experiment(s), comma separated")
	out := flag.String("out", "eval/results/raw", "output directory")
	quick := flag.Bool("quick", false, "fewer repetitions and configurations")
	flag.Parse()
	opts := bench.Options{OutDir: *out, Quick: *quick, Log: func(f string, a ...any) {
		fmt.Fprintf(os.Stderr, time.Now().Format("15:04:05")+" "+f+"\n", a...)
	}}
	all := map[string]func(bench.Options) error{
		"verify": bench.Verify, "consensus": bench.Consensus, "bundle": bench.BundleSize,
		"e2e": bench.EndToEnd, "e2e_size": bench.EndToEndSize, "propagation": bench.Propagation,
		"contention": bench.Contention, "faults": bench.Faults, "grinding": bench.Grinding,
	}
	order := []string{"verify", "consensus", "bundle", "e2e", "e2e_size", "propagation", "contention", "faults", "grinding"}
	var run []string
	if *exp == "all" {
		run = order
	} else {
		run = strings.Split(*exp, ",")
	}
	for _, name := range run {
		f, ok := all[name]
		if !ok {
			log.Fatalf("unknown experiment %q", name)
		}
		start := time.Now()
		if err := f(opts); err != nil {
			log.Fatalf("%s: %v", name, err)
		}
		opts.Log("%s done in %s", name, time.Since(start).Round(time.Second))
	}
}
