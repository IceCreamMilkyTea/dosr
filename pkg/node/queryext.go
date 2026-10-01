package node

import (
	"context"
	"encoding/json"
	"os"
	"sync/atomic"
	"syscall"

	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/dosr/dosr/pkg/app"
)

// StateQueryPath is an ABCI query path, answered by the node (not by
// the application), that returns the JSON encoding of the complete
// committed application state. The test harness uses it to take an
// atomic snapshot of a node that runs in another process; the
// application's own queries return one repository at a time, and a node
// that keeps committing blocks does not answer a sequence of them from
// one state.
const StateQueryPath = "/node/state"

// CrashPoint makes the node kill its own PROCESS with SIGKILL at a
// precise point of the commit of one block. It is meant for nodes run by
// cmd/dosrd under the test harness; never set it on an in-process node.
type CrashPoint struct {
	Height int64
	// AfterAppCommit selects the window:
	//
	// false: crash when CometBFT calls Commit, before the application
	// commits. On disk: block h is in the block store and the WAL, the
	// responses of FinalizeBlock are saved, the application and
	// CometBFT's state are at h-1. On restart the handshake must replay
	// block h against the application.
	//
	// true: crash when the application has committed durably, before
	// Commit returns. On disk: the application is at h, CometBFT's state
	// at h-1. On restart the handshake must NOT execute block h again
	// but bring CometBFT's state to h from the saved responses.
	AfterAppCommit bool
}

// queryExt wraps the application: it adds StateQueryPath and implements
// crash points. All other calls pass through unchanged.
type queryExt struct {
	abci.Application
	app    *app.App
	crash  *CrashPoint
	height *atomic.Int64 // of the block being executed
}

func (q queryExt) FinalizeBlock(ctx context.Context, req *abci.RequestFinalizeBlock) (*abci.ResponseFinalizeBlock, error) {
	q.height.Store(req.Height)
	return q.Application.FinalizeBlock(ctx, req)
}

func (q queryExt) Commit(ctx context.Context, req *abci.RequestCommit) (*abci.ResponseCommit, error) {
	hit := q.crash != nil && q.crash.Height == q.height.Load()
	if hit && !q.crash.AfterAppCommit {
		die()
	}
	res, err := q.Application.Commit(ctx, req)
	if hit {
		die()
	}
	return res, err
}

func die() {
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	select {} // never continue past the crash point
}

func (q queryExt) Query(ctx context.Context, req *abci.RequestQuery) (*abci.ResponseQuery, error) {
	if req.Path != StateQueryPath {
		return q.Application.Query(ctx, req)
	}
	st := q.app.Committed() // immutable once published
	b, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	return &abci.ResponseQuery{Code: 0, Value: b, Height: st.Height}, nil
}
