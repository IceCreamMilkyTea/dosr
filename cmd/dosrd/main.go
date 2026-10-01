// Command dosrd runs one DOSR node (CometBFT + the DOSR application in
// one process) from a home directory prepared with node.SaveConfig.
//
// It exists so that the test harness can run nodes as operating system
// processes and kill them with SIGKILL at arbitrary points.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dosr/dosr/pkg/node"
)

func main() {
	// Captured before anything else: the parent may die while the node
	// starts up, and an orphan is reparented (to PID 1) at that moment.
	ppid := os.Getppid()
	home := flag.String("home", "", "node home directory (contains "+node.ConfigFileName+")")
	p2pAddr := flag.String("p2p", "", "override the p2p listen address (host:port)")
	rpcAddr := flag.String("rpc", "", "override the RPC listen address (host:port)")
	logLevel := flag.String("log-level", "", "override the log level (none|error|info|debug)")
	crashBefore := flag.Int64("crash-before-commit", 0, "testing: SIGKILL this process when block `height` is about to be committed by the application")
	crashAfter := flag.Int64("crash-after-commit", 0, "testing: SIGKILL this process when the application has committed block `height`, before CometBFT learns of it")
	withParent := flag.Bool("exit-with-parent", false, "exit when the parent process exits")
	flag.Parse()
	if *home == "" {
		fmt.Fprintln(os.Stderr, "dosrd: --home is required")
		os.Exit(2)
	}
	cfg, err := node.LoadConfig(*home)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dosrd:", err)
		os.Exit(1)
	}
	if *p2pAddr != "" {
		cfg.P2PListen = *p2pAddr
	}
	if *rpcAddr != "" {
		cfg.RPCListen = *rpcAddr
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}

	switch {
	case *crashBefore > 0:
		cfg.Crash = &node.CrashPoint{Height: *crashBefore}
	case *crashAfter > 0:
		cfg.Crash = &node.CrashPoint{Height: *crashAfter, AfterAppCommit: true}
	}

	n, err := node.Start(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dosrd:", err)
		os.Exit(1)
	}
	fmt.Printf("dosrd: node %s started, p2p %s rpc %s height %d\n", n.ID(), cfg.P2PListen, cfg.RPCListen, n.Height())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	orphaned := make(chan struct{})
	if *withParent {
		go func() {
			// No parent-death signal on macOS: poll. PID 1 means the
			// parent was already gone when this process started.
			for ppid != 1 && os.Getppid() == ppid {
				time.Sleep(500 * time.Millisecond)
			}
			close(orphaned)
		}()
	}
	select {
	case s := <-sig:
		fmt.Printf("dosrd: %v, stopping\n", s)
	case <-orphaned:
		fmt.Println("dosrd: parent exited, stopping")
	}
	if err := n.Stop(); err != nil {
		fmt.Fprintln(os.Stderr, "dosrd: stop:", err)
		os.Exit(1)
	}
}
