package types

// Result codes of transaction execution. Code 0 is success; every other
// code means the transaction had NO effect on state. Codes are part of the
// replicated result (they are hashed into the block's results hash by
// CometBFT), so the mapping from failure to code must be deterministic.
const (
	CodeOK uint32 = 0

	// Stateless failures: the transaction can never be valid. An honest
	// proposer never includes such a transaction, and honest validators
	// reject proposals that contain one.
	CodeMalformed    uint32 = 1
	CodeBadSignature uint32 = 2
	CodeWrongChain   uint32 = 3

	// Stateful failures: the transaction is well-formed but does not
	// apply to the current state.
	CodeUnknownRepo   uint32 = 10
	CodeRepoExists    uint32 = 11
	CodeUnknownBranch uint32 = 12
	CodeStaleHead     uint32 = 13 // expected_head != current head
	CodeStalePolicy   uint32 = 14 // policy_version/expected_version != current
	CodeUnauthorized  uint32 = 15 // insufficient maintainer approvals

	// Evidence failures: bundle or receipt does not check out.
	CodeBadBundle     uint32 = 20
	CodeBadReceipt    uint32 = 21 // attestation invalid / untrusted notary / root mismatch
	CodeWrongProvider uint32 = 22 // server name, SPKI, method, path or headers not per policy
	CodeWrongModel    uint32 = 23
	CodeBadResponse   uint32 = 24 // HTTP status != 200 or unparsable response
	CodeNotApproved   uint32 = 25 // the model's verdict is "reject"
	CodeWrongBinding  uint32 = 26 // response names a different candidate
	CodeExpired       uint32 = 27 // receipt older than policy allows
	CodeFromFuture    uint32 = 28 // receipt timestamp ahead of block time beyond skew
	CodeUnreviewable  uint32 = 29 // diff too large / opaque / empty

	// Intent failures.
	CodeIntentRequired   uint32 = 40
	CodeIntentUnknown    uint32 = 41
	CodeIntentUsed       uint32 = 42
	CodeIntentMismatch   uint32 = 43
	CodeTooManyAttempts  uint32 = 44
	CodeIntentNotEnabled uint32 = 45

	// CodeInternal must never occur; it indicates a bug or local storage
	// failure. A node that would return it panics instead, because
	// continuing could diverge from the other replicas.
	CodeInternal uint32 = 99
)

// Codespace is the ABCI codespace of DOSR's codes.
const Codespace = "dosr"

// CodeName returns a short stable name for a code (used in events, logs
// and the evaluation's result tables).
func CodeName(c uint32) string {
	switch c {
	case CodeOK:
		return "ok"
	case CodeMalformed:
		return "malformed"
	case CodeBadSignature:
		return "bad_signature"
	case CodeWrongChain:
		return "wrong_chain"
	case CodeUnknownRepo:
		return "unknown_repo"
	case CodeRepoExists:
		return "repo_exists"
	case CodeUnknownBranch:
		return "unknown_branch"
	case CodeStaleHead:
		return "stale_head"
	case CodeStalePolicy:
		return "stale_policy"
	case CodeUnauthorized:
		return "unauthorized"
	case CodeBadBundle:
		return "bad_bundle"
	case CodeBadReceipt:
		return "bad_receipt"
	case CodeWrongProvider:
		return "wrong_provider"
	case CodeWrongModel:
		return "wrong_model"
	case CodeBadResponse:
		return "bad_response"
	case CodeNotApproved:
		return "not_approved"
	case CodeWrongBinding:
		return "wrong_binding"
	case CodeExpired:
		return "expired"
	case CodeFromFuture:
		return "from_future"
	case CodeUnreviewable:
		return "unreviewable"
	case CodeIntentRequired:
		return "intent_required"
	case CodeIntentUnknown:
		return "intent_unknown"
	case CodeIntentUsed:
		return "intent_used"
	case CodeIntentMismatch:
		return "intent_mismatch"
	case CodeTooManyAttempts:
		return "too_many_attempts"
	case CodeIntentNotEnabled:
		return "intent_not_enabled"
	case CodeInternal:
		return "internal"
	}
	return "unknown"
}
