// Command dosr-dev starts a complete local DOSR deployment for demos:
// an N-validator chain on localhost (default 4), the mock LLM provider
// (HTTPS) and a notary that trusts it. It prints everything the `dosr`
// CLI needs and runs until interrupted.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dosr/dosr/pkg/bench"
	"github.com/dosr/dosr/pkg/dosrtest"
	"github.com/dosr/dosr/pkg/llm"
	"github.com/dosr/dosr/pkg/node"
	"github.com/dosr/dosr/pkg/testnet"
)

func main() {
	n := flag.Int("validators", 4, "number of validators")
	dir := flag.String("dir", "", "directory for node homes (default: temporary)")
	fast := flag.Bool("fast", false, "fast consensus timeouts")
	flag.Parse()

	stack, err := bench.StartStack(llm.LatencyFast, nil, false)
	if err != nil {
		fail(err)
	}
	defer stack.Close()
	opts := testnet.Options{Validators: *n, HTTPRPC: true, Dir: *dir, KeepDir: *dir != "", LogLevel: "error", ChainID: "dosr"}
	if *fast {
		opts.Timeouts = node.FastTimeouts()
	} else {
		opts.Timeouts = node.DefaultTimeouts()
	}
	c, err := testnet.Start(opts)
	if err != nil {
		fail(err)
	}
	defer c.Close()

	fmt.Printf("chain id:        %s\n", c.ChainID())
	for i := 0; i < c.N(); i++ {
		fmt.Printf("node %d RPC:      http://%s\n", i, c.RPCAddr(i))
	}
	fmt.Printf("provider host:   %s   (policy -host)\n", stack.Host)
	fmt.Printf("provider key:    %s   (export DOSR_API_KEY=...)\n", stack.APIKey)
	fmt.Printf("notary URL:      %s\n", stack.Notary.URL())
	fmt.Printf("notary pubkey:   %x   (policy -notary)\n", dosrtest.Pub(stack.NotaryK))
	fmt.Printf("reject marker:   a line containing %q in an added line makes the mock reviewer reject\n", llm.RejectMarker)
	fmt.Println("running; Ctrl-C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	tick := time.NewTicker(30 * time.Second)
	for {
		select {
		case <-sig:
			return
		case <-tick.C:
			fmt.Printf("height %d, provider calls %d\n", c.MaxHeight(), stack.Provider.Stats().Calls)
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "dosr-dev:", err)
	os.Exit(1)
}
