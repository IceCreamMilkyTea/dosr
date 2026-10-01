package app

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/dosr/dosr/pkg/gitobj"
	"github.com/dosr/dosr/pkg/types"
)

// Query paths (all answer from the last committed state; responses are
// JSON unless noted):
//
//	/repos                          list of repository IDs
//	/repo/<repo>                    Repo
//	/head/<repo>/<branch>           Branch
//	/history/<repo>/<branch>        data = "from,limit" (optional); []HistoryEntry
//	/intent/<id>                    Intent
//	/reputation                     []ReputationEntry, sorted by hex pubkey
//	/reputation/<hex pubkey>        Reputation
//	/object/<repo>/<id>             raw: type byte || object data
//	/stats                          StatsSnapshot (node-local, not replicated)
//
// Queries are served by a single node and are NOT proofs; a light client
// would need Merkle proofs against the app hash (future work).
func (a *App) Query(_ context.Context, req *abci.RequestQuery) (*abci.ResponseQuery, error) {
	st := a.Committed()
	parts := strings.Split(strings.TrimPrefix(req.Path, "/"), "/")
	notFound := func(what string) (*abci.ResponseQuery, error) {
		return &abci.ResponseQuery{Code: 1, Log: what + " not found", Codespace: types.Codespace, Height: st.Height}, nil
	}
	ok := func(v any) (*abci.ResponseQuery, error) {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		return &abci.ResponseQuery{Code: 0, Value: b, Height: st.Height}, nil
	}
	switch {
	case len(parts) == 1 && parts[0] == "repos":
		return ok(sortedKeys(st.Repos))
	case len(parts) == 1 && parts[0] == "stats":
		return ok(a.StatsSnapshot())
	case len(parts) == 2 && parts[0] == "repo":
		r, found := st.Repos[parts[1]]
		if !found {
			return notFound("repo")
		}
		return ok(r)
	case len(parts) >= 3 && parts[0] == "head":
		r, found := st.Repos[parts[1]]
		if !found {
			return notFound("repo")
		}
		b, found := r.Branches[strings.Join(parts[2:], "/")]
		if !found {
			return notFound("branch")
		}
		return ok(b)
	case len(parts) >= 3 && parts[0] == "history":
		repo, branch := parts[1], strings.Join(parts[2:], "/")
		r, found := st.Repos[repo]
		if !found {
			return notFound("repo")
		}
		b, found := r.Branches[branch]
		if !found {
			return notFound("branch")
		}
		from, limit := uint64(1), uint64(100)
		if f := strings.Split(string(req.Data), ","); len(f) == 2 {
			if v, err := strconv.ParseUint(f[0], 10, 64); err == nil && v >= 1 {
				from = v
			}
			if v, err := strconv.ParseUint(f[1], 10, 64); err == nil && v >= 1 && v <= 1000 {
				limit = v
			}
		}
		out := []*HistoryEntry{}
		// Only entries up to the Seq of the state snapshot we answer
		// from, so the answer is consistent with Height.
		for seq := from; seq <= b.Seq && uint64(len(out)) < limit; seq++ {
			e, err := a.History(repo, branch, seq)
			if err != nil {
				return nil, err
			}
			if e == nil {
				break
			}
			out = append(out, e)
		}
		return ok(out)
	case len(parts) == 2 && parts[0] == "intent":
		in, found := st.Intents[parts[1]]
		if !found {
			return notFound("intent")
		}
		return ok(in)
	case len(parts) == 1 && parts[0] == "reputation":
		out := []ReputationEntry{}
		for _, k := range sortedKeys(st.Reputation) {
			out = append(out, ReputationEntry{PubKey: k, Reputation: *st.Reputation[k]})
		}
		return ok(out)
	case len(parts) == 2 && parts[0] == "reputation":
		r, found := st.Reputation[strings.ToLower(parts[1])]
		if !found {
			return notFound("reputation")
		}
		return ok(r)
	case len(parts) == 3 && parts[0] == "object":
		id, err := gitobj.ParseID(parts[2])
		if err != nil {
			return notFound("object")
		}
		v, err := a.db.Get(objKey(parts[1], id))
		if err != nil {
			return nil, err
		}
		if len(v) == 0 {
			return notFound("object")
		}
		return &abci.ResponseQuery{Code: 0, Value: v, Height: st.Height}, nil
	}
	return notFound("path")
}

// ReputationEntry is one row of the /reputation listing.
type ReputationEntry struct {
	PubKey string `json:"pubkey"`
	Reputation
}

// History returns a committed history entry, or nil if there is none.
func (a *App) History(repo, branch string, seq uint64) (*HistoryEntry, error) {
	v, err := a.db.Get(histKey(repo, branch, seq))
	if err != nil {
		return nil, err
	}
	if len(v) == 0 {
		return nil, nil
	}
	var e HistoryEntry
	if err := json.Unmarshal(v, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// Objects returns the committed object store of a repository.
func (a *App) Objects(repo string) gitobj.Store {
	return readOnlyStore{newObjLayer(a.db, nil).Repo(repo)}
}

type readOnlyStore struct{ gitobj.Store }

func (readOnlyStore) Put(gitobj.Object) (gitobj.ID, error) {
	panic("app: committed object store is read-only")
}
