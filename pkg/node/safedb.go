package node

import (
	"sync"
	"sync/atomic"

	dbm "github.com/cometbft/cometbft-db"
)

// safeDB makes a database safe to close while goroutines that read from
// it may still be running.
//
// Why: CometBFT's Node.OnStop closes the block store, but the consensus
// reactor's per-peer gossip routines only notice that the node stopped
// when they wake up from their sleep (peer_gossip_sleep_duration,
// peer_query_maj23_sleep_duration). A routine that was past its
// IsRunning check when the node stopped reads from the closed store,
// gets "leveldb: closed", and the block store PANICS on any read error.
// In a standalone node the process is exiting anyway; with several nodes
// in one test process the panic of a node that was stopped on purpose
// kills all of them. After Close, reads therefore answer "not found"
// (which the callers handle) instead of failing; writes still fail.
// Close is idempotent.
type safeDB struct {
	dbm.DB
	closed atomic.Bool
	once   sync.Once
	err    error
}

func newSafeDB(db dbm.DB) *safeDB { return &safeDB{DB: db} }

func (s *safeDB) Get(key []byte) ([]byte, error) {
	if s.closed.Load() {
		return nil, nil
	}
	v, err := s.DB.Get(key)
	if err != nil && s.closed.Load() {
		return nil, nil
	}
	return v, err
}

func (s *safeDB) Has(key []byte) (bool, error) {
	if s.closed.Load() {
		return false, nil
	}
	ok, err := s.DB.Has(key)
	if err != nil && s.closed.Load() {
		return false, nil
	}
	return ok, err
}

func (s *safeDB) Close() error {
	s.once.Do(func() {
		s.closed.Store(true)
		s.err = s.DB.Close()
	})
	return s.err
}
