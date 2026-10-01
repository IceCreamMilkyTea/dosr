-------------------------------- MODULE DOSR --------------------------------
(***************************************************************************)
(* DOSR - a decentralised Git host whose branch head only advances when a  *)
(* notarised LLM review approved the candidate commit.                     *)
(*                                                                         *)
(* What is modelled                                                        *)
(*   - one repository, one branch                                          *)
(*   - the BFT consensus layer as a TOTAL-ORDER BROADCAST: the variable    *)
(*     `log` is the single, final, global sequence of transactions         *)
(*   - replicas that apply the log in order, may lag, crash and restart    *)
(*   - the notarised LLM call as an oracle that adds a record to the set   *)
(*     `receipts`; the verdict is chosen nondeterministically              *)
(*   - honest and Byzantine contributors, honest and Byzantine maintainers *)
(*   - optionally (IntentsEnabled) the ReviewIntent anti-grinding          *)
(*     extension                                                           *)
(*                                                                         *)
(* Every validity check of the state machine is wrapped in G("name").      *)
(* The real protocol has Guards = AllGuards.  A MUTANT is obtained by      *)
(* removing one name from Guards; see spec/mutants/.                       *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Commits,          \* finite set of commit ids
    None,             \* "no commit": the head of an empty branch
    Parent,           \* [Commits -> Commits \cup {None}], a forest
    PolicyHashes,     \* finite set of policy hashes
    InitPolicy,       \* the policy hash installed at repository creation
    Replicas,         \* correct replicas (Byzantine ones are hidden inside
                      \* the total-order-broadcast assumption)
    Honest,           \* honest contributors
    Byzantine,        \* Byzantine contributors
    Maintainers,      \* keys allowed to co-sign a policy update
    ByzMaintainers,   \* the Byzantine ones among them
    Outsider,         \* a key that is not a maintainer
    Threshold,        \* number of maintainer signatures required
    IntentsEnabled,   \* BOOLEAN: is the ReviewIntent extension switched on
    MaxAttempts,      \* max intents per (base, candidate)
    FullAdversary,    \* BOOLEAN: TRUE = Byzantine parties choose among ALL
                      \* requests / transactions; FALSE = the single-fault
                      \* reduction described at ByzAccept
    UniqueSessions,   \* BOOLEAN: give every LLM call its own session id
    TrackEpoch,       \* BOOLEAN: record the ghost field `epoch` in receipts
    Guards,           \* the set of checks that are switched on
    \* ---- bounds that make the model finite -------------------------------
    MaxLogLen,        \* max length of the log
    MaxReceipts,      \* max number of notarised LLM calls
    MaxRejects,       \* max number of LLM calls answered "reject"
    MaxByzCalls,      \* max LLM calls made by Byzantine contributors
    MaxByzTxs,        \* max transactions submitted by Byzantine parties
    MaxPolicyTxs,     \* max UpdatePolicy transactions in the log
    MaxCrashes        \* max number of replica crashes

VARIABLES
    log,        \* Seq(Tx): the output of total-order broadcast
    receipts,   \* the set of GENUINELY ISSUED receipts
    applied,    \* [Replicas -> Nat]: length of the prefix a replica applied
    rstate,     \* [Replicas -> State]: volatile state of a replica
    pidx,       \* [Replicas -> Nat]: length of the persisted prefix
    pstate,     \* [Replicas -> State]: persisted state of a replica
    up,         \* [Replicas -> BOOLEAN]
    crashes,    \* number of crashes so far
    byzCalls,   \* number of Byzantine LLM calls so far
    byzTxs      \* number of Byzantine transactions so far

vars == <<log, receipts, applied, rstate, pidx, pstate, up, crashes,
          byzCalls, byzTxs>>

AllGuards ==
    { "head",          \* AcceptCommit: head = expectedHead
      "member",        \* AcceptCommit: receipt \in Receipts (signature check)
      "verdict",       \* AcceptCommit: receipt.verdict = approve
      "base",          \* AcceptCommit: receipt.base = expectedHead
      "candidate",     \* AcceptCommit: receipt.candidate = candidate
      "policy",        \* AcceptCommit: receipt.policy = current policy hash
      "parent",        \* AcceptCommit: parent(candidate) = expectedHead
      "version",       \* UpdatePolicy: expectedVersion = current version
      "auth",          \* UpdatePolicy: >= Threshold maintainer signatures
      "intent",        \* AcceptCommit: nonce belongs to a registered intent
                       \*               for the same (base, candidate)
      "intentUnused",  \* AcceptCommit: that intent was not consumed before
      "attemptCap",    \* ReviewIntent: < MaxAttempts intents for the pair
      "notaryIntent",  \* notary: the nonce in the request is registered on
                       \*         chain for the same (base, candidate)
      "notaryOnce",    \* notary: at most one session per nonce
      "restartIndex" } \* replica: restart restores index AND state together

G(g) == g \in Guards

Approve == "approve"
Reject  == "reject"
NoNonce == 0

Heads        == Commits \cup {None}
NonceChoices == IF IntentsEnabled THEN 1..MaxLogLen ELSE {NoNonce}
Signers      == Maintainers \cup {Outsider}

ASSUME /\ None \notin Commits
       /\ Parent \in [Commits -> Heads]
       /\ InitPolicy \in PolicyHashes
       /\ ByzMaintainers \subseteq Maintainers
       /\ Outsider \notin Maintainers
       /\ Threshold \in 1..Cardinality(Maintainers)
       \* the trust assumption on maintainers:
       /\ Cardinality(ByzMaintainers) < Threshold
       /\ Guards \subseteq AllGuards
       /\ IntentsEnabled \in BOOLEAN /\ FullAdversary \in BOOLEAN
       /\ UniqueSessions \in BOOLEAN /\ TrackEpoch \in BOOLEAN

(***************************************************************************)
(* Receipts.                                                               *)
(*   base, candidate, policy, nonce : what the review REQUEST was about    *)
(*   verdict                        : what the LLM answered                *)
(*   sid   : the notary session.  sid = 0 is never issued: it marks the    *)
(*           records made up by the adversary (no valid signature).        *)
(*           If UniqueSessions, the k-th LLM call gets sid = k, so two     *)
(*           calls never yield the same receipt.  Otherwise every genuine  *)
(*           receipt has sid = 1 and two calls with the same request and   *)
(*           the same verdict are the same element of `receipts` (a sound  *)
(*           quotient, see README).                                        *)
(*   epoch : GHOST.  The policy version of the chain when the call was     *)
(*           made (0 if not TrackEpoch).  Never read by the protocol, only *)
(*           by the property PolicyEpoch.                                  *)
(***************************************************************************)
ReceiptRecords ==
    [base: Heads, candidate: Commits, policy: PolicyHashes,
     nonce: NonceChoices, verdict: {Approve, Reject},
     sid: 0..MaxReceipts, epoch: 0..(MaxPolicyTxs + 1)]

AcceptTx(h, c, r) ==
    [type |-> "Accept", expectedHead |-> h, candidate |-> c, receipt |-> r]
PolicyTx(v, p, S) ==
    [type |-> "Policy", expectedVersion |-> v, newHash |-> p, signers |-> S]
IntentTx(b, c) ==
    [type |-> "Intent", base |-> b, candidate |-> c]

(***************************************************************************)
(* The replicated state machine.                                           *)
(*   certs and pauth are GHOST fields: they record what the state machine  *)
(*   saw when it applied a transaction.  No guard reads them.              *)
(***************************************************************************)
InitState ==
    [ head    |-> None,
      history |-> << >>,
      pver    |-> 1,
      phash   |-> InitPolicy,
      height  |-> 0,          \* number of transactions applied
      intents |-> {},         \* registered review intents
      used    |-> {},         \* nonces of consumed intents
      certs   |-> << >>,      \* GHOST: one certificate per accepted commit
      pauth   |-> << >> ]     \* GHOST: one entry per applied policy update

IntentsFor(s, b, c) ==
    {i \in s.intents : i.base = b /\ i.candidate = c}

AcceptValid(s, tx) ==
    LET r == tx.receipt IN
    /\ G("head")      => s.head = tx.expectedHead
    /\ G("member")    => r \in receipts
    /\ G("verdict")   => r.verdict = Approve
    /\ G("base")      => r.base = tx.expectedHead
    /\ G("candidate") => r.candidate = tx.candidate
    /\ G("policy")    => r.policy = s.phash
    /\ G("parent")    => Parent[tx.candidate] = tx.expectedHead
    /\ IntentsEnabled =>
         /\ G("intent") =>
              \E i \in IntentsFor(s, tx.expectedHead, tx.candidate) :
                  i.nonce = r.nonce
         /\ G("intentUnused") => r.nonce \notin s.used

PolicyValid(s, tx) ==
    /\ G("version") => tx.expectedVersion = s.pver
    /\ G("auth")    => Cardinality(tx.signers \cap Maintainers) >= Threshold

IntentValid(s, tx) ==
    /\ IntentsEnabled
    /\ G("attemptCap") =>
         Cardinality(IntentsFor(s, tx.base, tx.candidate)) < MaxAttempts

\* An invalid transaction is a no-op, except that it occupies a slot.
ApplyTx(s, tx) ==
    LET t == [s EXCEPT !.height = @ + 1] IN
    CASE tx.type = "Accept" ->
           IF AcceptValid(s, tx)
           THEN [t EXCEPT
                   !.head    = tx.candidate,
                   !.history = Append(@, tx.candidate),
                   !.used    = IF IntentsEnabled
                               THEN @ \cup {tx.receipt.nonce} ELSE @,
                   !.certs   = Append(@,
                       [ candidate  |-> tx.candidate,
                         receipt    |-> tx.receipt,
                         headBefore |-> s.head,
                         policy     |-> [ver |-> s.pver, hash |-> s.phash],
                         index      |-> s.height + 1 ])]
           ELSE t
      [] tx.type = "Policy" ->
           IF PolicyValid(s, tx)
           THEN [t EXCEPT !.pver  = @ + 1,
                          !.phash = tx.newHash,
                          !.pauth = Append(@,
                              [ signers  |-> tx.signers,
                                expected |-> tx.expectedVersion,
                                version  |-> s.pver ])]
           ELSE t
      [] tx.type = "Intent" ->
           IF IntentValid(s, tx)
           THEN [t EXCEPT !.intents = @ \cup
                    {[ base |-> tx.base, candidate |-> tx.candidate,
                       nonce |-> s.height + 1 ]}]   \* position in the log
           ELSE t

\* The state after the first n transactions of the log.
RECURSIVE Replay(_)
Replay(n) == IF n = 0 THEN InitState ELSE ApplyTx(Replay(n - 1), log[n])

Chain == Replay(Len(log))      \* the state of a fully caught-up replica

-----------------------------------------------------------------------------
(***************************************************************************)
(* Actions                                                                 *)
(***************************************************************************)
Init ==
    /\ log      = << >>
    /\ receipts = {}
    /\ applied  = [r \in Replicas |-> 0]
    /\ rstate   = [r \in Replicas |-> InitState]
    /\ pidx     = [r \in Replicas |-> 0]
    /\ pstate   = [r \in Replicas |-> InitState]
    /\ up       = [r \in Replicas |-> TRUE]
    /\ crashes  = 0
    /\ byzCalls = 0
    /\ byzTxs   = 0

InLog(tx)       == \E i \in 1..Len(log) : log[i] = tx
NumPolicyTxs    == Cardinality({i \in 1..Len(log) : log[i].type = "Policy"})
NumRejects      == Cardinality({r \in receipts : r.verdict = Reject})
Views           == {rstate[r] : r \in {x \in Replicas : up[x]}}

(***************************************************************************)
(* The notarised LLM call.  The contributor chooses the request            *)
(* (b, c, p, n); the LLM chooses the verdict v; the notary attests the     *)
(* pair truthfully.  With intents, the notary additionally refuses to      *)
(* attest a session whose nonce is not registered on chain for (b, c), or  *)
(* whose nonce it attested before.                                         *)
(***************************************************************************)
Notarise(b, c, p, n, v) ==
    /\ Cardinality(receipts) < MaxReceipts
    /\ v = Reject => NumRejects < MaxRejects
    /\ IntentsEnabled =>
         /\ G("notaryIntent") =>
              \E s \in Views : \E i \in IntentsFor(s, b, c) : i.nonce = n
         /\ G("notaryOnce") => \A r \in receipts : r.nonce # n
    /\ receipts' = receipts \cup
         {[ base |-> b, candidate |-> c, policy |-> p, nonce |-> n,
            verdict |-> v,
            sid     |-> IF UniqueSessions THEN Cardinality(receipts) + 1 ELSE 1,
            epoch   |-> IF TrackEpoch THEN Chain.pver ELSE 0 ]}

Submit(tx) ==
    /\ Len(log) < MaxLogLen
    /\ log' = Append(log, tx)

\* ---- honest contributors -------------------------------------------------
\* An honest contributor reads head and policy from some replica (which may
\* lag), picks a child of that head, and asks for a review, unless an
\* approving receipt for exactly this request already exists.
HonestCall(u) ==
    \E s \in Views, c \in Commits, n \in NonceChoices, v \in {Approve, Reject} :
        /\ Parent[c] = s.head
        /\ ~ \E r \in receipts : /\ r.base = s.head /\ r.candidate = c
                                 /\ r.policy = s.phash /\ r.verdict = Approve
        /\ IntentsEnabled =>
             /\ n \notin s.used
             /\ \E i \in IntentsFor(s, s.head, c) : i.nonce = n
        /\ Notarise(s.head, c, s.phash, n, v)
        /\ UNCHANGED <<log, applied, rstate, pidx, pstate, up, crashes,
                       byzCalls, byzTxs>>

\* An honest contributor submits an approving receipt together with the
\* (base, candidate) it was issued for, if according to some replica the
\* receipt is still current.  It never submits the same transaction twice.
HonestAccept(u) ==
    \E r \in receipts, s \in Views :
        /\ r.verdict = Approve
        /\ Parent[r.candidate] = r.base
        /\ s.head = r.base /\ s.phash = r.policy
        /\ ~ InLog(AcceptTx(r.base, r.candidate, r))
        /\ Submit(AcceptTx(r.base, r.candidate, r))
        /\ UNCHANGED <<receipts, applied, rstate, pidx, pstate, up, crashes,
                       byzCalls, byzTxs>>

\* With intents: register an intent for a child of the head, unless there is
\* an intent for it that has not been notarised yet, or one is in flight.
HonestIntent(u) ==
    /\ IntentsEnabled
    /\ \E s \in Views, c \in Commits :
        /\ Parent[c] = s.head
        /\ ~ \E i \in IntentsFor(s, s.head, c) :
                 \A r \in receipts : r.nonce # i.nonce
        /\ Cardinality(IntentsFor(s, s.head, c)) < MaxAttempts
        /\ ~ \E k \in (s.height + 1)..Len(log) :
                 log[k] = IntentTx(s.head, c)
        /\ Submit(IntentTx(s.head, c))
        /\ UNCHANGED <<receipts, applied, rstate, pidx, pstate, up, crashes,
                       byzCalls, byzTxs>>

\* ---- maintainers ---------------------------------------------------------
\* A policy update that a threshold of maintainers signed.  Which
\* maintainers signed is irrelevant beyond their number (the state machine
\* only counts), so all of them sign.
HonestPolicy ==
    \E s \in Views, p \in PolicyHashes :
        /\ NumPolicyTxs < MaxPolicyTxs
        /\ Submit(PolicyTx(s.pver, p, Maintainers))
        /\ UNCHANGED <<receipts, applied, rstate, pidx, pstate, up, crashes,
                       byzCalls, byzTxs>>

\* ---- Byzantine contributors and maintainers -------------------------------
\* Any request whatsoever may be sent to the LLM.  (Reduced adversary: a
\* REJECTED request whose candidate is not a child of its base is left out;
\* a transaction carrying such a receipt fails two static checks.)
ByzCall(u) ==
    \E b \in Heads, c \in Commits, p \in PolicyHashes, n \in NonceChoices,
       v \in {Approve, Reject} :
        /\ byzCalls < MaxByzCalls
        /\ FullAdversary \/ v = Approve \/ Parent[c] = b
        /\ byzCalls' = byzCalls + 1
        /\ Notarise(b, c, p, n, v)
        /\ UNCHANGED <<log, applied, rstate, pidx, pstate, up, crashes,
                       byzTxs>>

\* Records the adversary can make up.  They carry sid = 0, so they are not
\* in `receipts` and never will be (unforgeability of the notary signature).
Forged(b, c, p, n, v) ==
    [ base |-> b, candidate |-> c, policy |-> p, nonce |-> n, verdict |-> v,
      sid |-> 0, epoch |-> 0 ]

AllForgeries ==
    {Forged(b, c, p, n, v) : b \in Heads, c \in Commits, p \in PolicyHashes,
                             n \in NonceChoices, v \in {Approve, Reject}}

\* FULL adversary: any expected head, any candidate, and any existing
\* receipt (replay, also of other people's receipts, also paired with the
\* wrong commit or the wrong head) or any forged record.
FullAcceptTxs ==
    {AcceptTx(h, c, r) : h \in Heads, c \in Commits,
                         r \in receipts \cup AllForgeries}

\* REDUCED adversary.  Five of the checks of AcceptCommit are STATIC, i.e.
\* they depend on the transaction alone: member, verdict, base, candidate,
\* parent.  A transaction that fails two or more static checks is rejected
\* by the real state machine and by every mutant that lacks ONE guard, in
\* every state; it is a no-op that occupies a log slot.  All such
\* transactions are therefore represented by a single one, JunkTx.  The
\* reduced adversary submits JunkTx or a transaction that fails at most one
\* static check.  The dynamic checks (head, policy, intent) are not
\* restricted in any way.
JunkTx ==
    LET c == CHOOSE x \in Commits : TRUE IN
    AcceptTx(None, c,
             Forged(None, c, InitPolicy, CHOOSE n \in NonceChoices : TRUE,
                    Reject))

ReducedAcceptTxs ==
    \* genuine receipt with its own (base, candidate): fails no static
    \* check, or only `verdict`, or only `parent`
    {AcceptTx(r.base, r.candidate, r) : r \in receipts}
    \* fails only `base`: receipt issued for another base
    \cup {AcceptTx(Parent[r.candidate], r.candidate, r) :
             r \in {x \in receipts : x.verdict = Approve}}
    \* fails only `candidate`: receipt issued for a sibling
    \cup UNION {{AcceptTx(r.base, c, r) :
                   c \in {x \in Commits : Parent[x] = r.base}} :
                r \in {x \in receipts : x.verdict = Approve}}
    \* fails only `member`: forged approval, otherwise perfectly bound
    \cup {AcceptTx(Parent[c], c, Forged(Parent[c], c, p, n, Approve)) :
             c \in Commits, p \in PolicyHashes, n \in NonceChoices}
    \cup {JunkTx}

ByzAccept(u) ==
    \E tx \in IF FullAdversary THEN FullAcceptTxs ELSE ReducedAcceptTxs :
        /\ byzTxs < MaxByzTxs
        /\ byzTxs' = byzTxs + 1
        /\ Submit(tx)
        /\ UNCHANGED <<receipts, applied, rstate, pidx, pstate, up, crashes,
                       byzCalls>>

ByzIntent(u) ==
    /\ IntentsEnabled
    /\ \E b \in Heads, c \in Commits :
        /\ byzTxs < MaxByzTxs
        /\ byzTxs' = byzTxs + 1
        /\ Submit(IntentTx(b, c))
        /\ UNCHANGED <<receipts, applied, rstate, pidx, pstate, up, crashes,
                       byzCalls>>

\* Byzantine maintainers sign anything, but cannot produce the signatures of
\* honest maintainers.  The state machine counts maintainer signatures, so
\* the adversary's best signer set is the largest one (the full adversary
\* tries the others as well).
ByzSignerSets ==
    IF FullAdversary
    THEN (SUBSET (ByzMaintainers \cup {Outsider})) \ {{}}
    ELSE {ByzMaintainers \cup {Outsider}}

ByzPolicy ==
    \E v \in 1..(MaxPolicyTxs + 1), p \in PolicyHashes, S \in ByzSignerSets :
        /\ Byzantine # {} \/ ByzMaintainers # {}
        /\ NumPolicyTxs < MaxPolicyTxs
        /\ byzTxs < MaxByzTxs
        /\ byzTxs' = byzTxs + 1
        /\ Submit(PolicyTx(v, p, S))
        /\ UNCHANGED <<receipts, applied, rstate, pidx, pstate, up, crashes,
                       byzCalls>>

\* ---- replicas ------------------------------------------------------------
Apply(r) ==
    /\ up[r]
    /\ applied[r] < Len(log)
    /\ rstate'  = [rstate  EXCEPT ![r] = ApplyTx(@, log[applied[r] + 1])]
    /\ applied' = [applied EXCEPT ![r] = @ + 1]
    /\ UNCHANGED <<log, receipts, pidx, pstate, up, crashes, byzCalls, byzTxs>>

\* Persistence is only interesting if replicas can crash.
Persist(r) ==
    /\ MaxCrashes > 0
    /\ up[r]
    /\ pidx[r] < applied[r]
    /\ pidx'   = [pidx   EXCEPT ![r] = applied[r]]
    /\ pstate' = [pstate EXCEPT ![r] = rstate[r]]
    /\ UNCHANGED <<log, receipts, applied, rstate, up, crashes, byzCalls,
                   byzTxs>>

Crash(r) ==
    /\ up[r]
    /\ crashes < MaxCrashes
    /\ crashes' = crashes + 1
    /\ up' = [up EXCEPT ![r] = FALSE]
    /\ UNCHANGED <<log, receipts, applied, rstate, pidx, pstate, byzCalls,
                   byzTxs>>

\* Restart: the volatile state is gone, resume from the persisted prefix.
Restart(r) ==
    /\ ~ up[r]
    /\ up'      = [up      EXCEPT ![r] = TRUE]
    /\ rstate'  = [rstate  EXCEPT ![r] = pstate[r]]
    /\ applied' = IF G("restartIndex")
                  THEN [applied EXCEPT ![r] = pidx[r]]
                  ELSE applied       \* MUTANT: forgets to rewind the index
    /\ UNCHANGED <<log, receipts, pidx, pstate, crashes, byzCalls, byzTxs>>

HonestNext ==
    \/ \E u \in Honest : HonestCall(u) \/ HonestAccept(u) \/ HonestIntent(u)
    \/ HonestPolicy

ByzNext ==
    \/ \E u \in Byzantine : ByzCall(u) \/ ByzAccept(u) \/ ByzIntent(u)
    \/ ByzPolicy

ReplicaNext ==
    \E r \in Replicas : Apply(r) \/ Persist(r) \/ Crash(r) \/ Restart(r)

Next == HonestNext \/ ByzNext \/ ReplicaNext

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(***************************************************************************)
(* Safety properties.  XxxIn(s) is the property of one state-machine state *)
(* s; the invariant Xxx asserts it of every replica.                       *)
(***************************************************************************)
States == {rstate[r] : r \in Replicas} \cup {pstate[r] : r \in Replicas}

IsPrefix(a, b) ==
    /\ Len(a) <= Len(b)
    /\ \A i \in 1..Len(a) : a[i] = b[i]

NoDuplicates(q) ==
    \A i, j \in 1..Len(q) : i # j => q[i] # q[j]

TypeOK ==
    /\ receipts \subseteq ReceiptRecords
    /\ \A r \in receipts : r.sid # 0
    /\ UniqueSessions => \A r1, r2 \in receipts : r1.sid = r2.sid => r1 = r2
    /\ Len(log) <= MaxLogLen
    /\ \A i \in 1..Len(log) : log[i].type \in {"Accept", "Policy", "Intent"}
    /\ applied \in [Replicas -> 0..MaxLogLen]
    /\ pidx    \in [Replicas -> 0..MaxLogLen]
    /\ up      \in [Replicas -> BOOLEAN]
    /\ crashes \in 0..MaxCrashes
    /\ byzCalls \in 0..MaxByzCalls
    /\ byzTxs   \in 0..MaxByzTxs
    /\ \A s \in States :
         /\ s.head \in Heads
         /\ s.history \in Seq(Commits)
         /\ s.pver \in 1..(MaxPolicyTxs + 1)
         /\ s.phash \in PolicyHashes
         /\ s.height \in 0..MaxLogLen
         /\ Len(s.certs) = Len(s.history)

\* 1. CertifiedHistory ------------------------------------------------------
\* Every commit of the history was accepted by a transaction of the log that
\* carried a genuinely issued, approving receipt for exactly that
\* (base, candidate), under the policy that was current when the transaction
\* was applied.
CertifiedHistoryIn(s) ==
    /\ Len(s.certs) = Len(s.history)
    /\ \A i \in 1..Len(s.history) :
         LET c  == s.certs[i]
             tx == log[c.index]
         IN /\ c.candidate = s.history[i]
            /\ c.headBefore = IF i = 1 THEN None ELSE s.history[i - 1]
            /\ tx = AcceptTx(c.headBefore, c.candidate, c.receipt)
            /\ c.receipt \in receipts
            /\ c.receipt.verdict   = Approve
            /\ c.receipt.base      = c.headBefore
            /\ c.receipt.candidate = c.candidate
            /\ c.receipt.policy    = c.policy.hash
CertifiedHistory == \A s \in States : CertifiedHistoryIn(s)

\* 2. LinearHistory ---------------------------------------------------------
LinearHistoryIn(s) ==
    /\ \A i \in 1..Len(s.history) :
         Parent[s.history[i]] = IF i = 1 THEN None ELSE s.history[i - 1]
    /\ NoDuplicates(s.history)
    /\ s.head = IF s.history = << >> THEN None
                ELSE s.history[Len(s.history)]
LinearHistory == \A s \in States : LinearHistoryIn(s)

\* 3. NoStaleAccept ---------------------------------------------------------
\* A receipt obtained for base H is only ever used while head = H.
NoStaleAcceptIn(s) ==
    \A i \in 1..Len(s.certs) : s.certs[i].receipt.base = s.certs[i].headBefore
NoStaleAccept == \A s \in States : NoStaleAcceptIn(s)

\* 4. ReplicaAgreement ------------------------------------------------------
PrefixConsistency ==
    \A r1, r2 \in Replicas :
        \/ IsPrefix(rstate[r1].history, rstate[r2].history)
        \/ IsPrefix(rstate[r2].history, rstate[r1].history)

\* A replica's state is a function of the prefix it applied (and so two
\* replicas that applied the same prefix are in the same state).
Determinism ==
    \A r \in Replicas :
        /\ pidx[r] <= applied[r] /\ applied[r] <= Len(log)
        /\ rstate[r] = Replay(applied[r])
        /\ pstate[r] = Replay(pidx[r])

\* 5. PolicyBinding ---------------------------------------------------------
\* Every accept used a receipt issued under the policy that was current when
\* the accept was applied; hence after an update no receipt issued under the
\* replaced policy is accepted.
PolicyBindingIn(s) ==
    \A i \in 1..Len(s.certs) :
        s.certs[i].receipt.policy = s.certs[i].policy.hash
PolicyBinding == \A s \in States : PolicyBindingIn(s)

\* Every policy update that took effect was signed by a threshold of
\* maintainers FOR THE VERSION IT REPLACED, and versions go up one by one.
PolicyAuthorisedIn(s) ==
    /\ Len(s.pauth) = s.pver - 1
    /\ \A i \in 1..Len(s.pauth) :
         /\ Cardinality(s.pauth[i].signers \cap Maintainers) >= Threshold
         /\ s.pauth[i].version  = i
         /\ s.pauth[i].expected = i
PolicyAuthorised == \A s \in States : PolicyAuthorisedIn(s)

\* 6. NoReceiptReuse --------------------------------------------------------
NoReceiptReuseIn(s) ==
    \A i, j \in 1..Len(s.certs) :
        i # j => s.certs[i].receipt # s.certs[j].receipt
NoReceiptReuse == \A s \in States : NoReceiptReuseIn(s)

\* 7. Intents ---------------------------------------------------------------
\* Every accept consumed its own registered intent for the same pair.
IntentBindingIn(s) ==
    /\ \A i \in 1..Len(s.certs) :
         LET c == s.certs[i] IN
         /\ c.receipt.nonce \in s.used
         /\ \E n \in IntentsFor(s, c.headBefore, c.candidate) :
                n.nonce = c.receipt.nonce
    /\ \A i, j \in 1..Len(s.certs) :
         i # j => s.certs[i].receipt.nonce # s.certs[j].receipt.nonce
IntentBinding == IntentsEnabled => \A s \in States : IntentBindingIn(s)

\* BoundedAttempts: at most MaxAttempts LLM calls were ever notarised for a
\* given (base, candidate).  (With UniqueSessions every call is a distinct
\* receipt.  Without, two calls are only identified if request, nonce AND
\* verdict coincide, which the notary's once-per-nonce rule excludes.)
CallsFor(b, c) == {r \in receipts : r.base = b /\ r.candidate = c}
BoundedAttempts ==
    IntentsEnabled =>
        \A b \in Heads, c \in Commits : Cardinality(CallsFor(b, c)) <= MaxAttempts

-----------------------------------------------------------------------------
(***************************************************************************)
(* Properties that are NOT guaranteed.  They are here to be refuted.       *)
(***************************************************************************)
\* "A commit that the LLM rejected is never accepted."  False without
\* intents: approval grinding.
NoGrindingIn(s) ==
    \A i \in 1..Len(s.certs) :
        LET a == s.certs[i].receipt IN
        ~ \E r \in receipts :
            /\ r.verdict = Reject
            /\ r.base = a.base /\ r.candidate = a.candidate
            /\ r.policy = a.policy
            /\ UniqueSessions => r.sid < a.sid   \* the rejection came first
NoGrinding == \A s \in States : NoGrindingIn(s)

\* "A receipt is only accepted in the policy epoch in which it was issued."
\* False: receipts bind the policy HASH, which can be known before the
\* update is applied, and which can become current again after a roll-back.
PolicyEpochIn(s) ==
    \A i \in 1..Len(s.certs) :
        s.certs[i].receipt.epoch = s.certs[i].policy.ver
PolicyEpoch == \A s \in States : PolicyEpochIn(s)

\* Reachability witnesses, stated as invariants that must be VIOLATED; they
\* show that the model is not vacuous (accepts do happen).
NeverThreeAccepts == \A s \in States : Len(s.history) < 3
NeverAcceptAfterPolicyUpdate ==
    \A s \in States : \A i \in 1..Len(s.certs) : s.certs[i].policy.ver = 1

-----------------------------------------------------------------------------
(***************************************************************************)
(* Liveness                                                                *)
(***************************************************************************)
Fairness ==
    /\ \A r \in Replicas : WF_vars(Apply(r))
    /\ \A r \in Replicas : WF_vars(Restart(r))
    /\ \A u \in Honest : WF_vars(HonestCall(u))
    /\ \A u \in Honest : WF_vars(HonestAccept(u))
    /\ \A u \in Honest : WF_vars(HonestIntent(u))

LiveSpec == Spec /\ Fairness

AllAccepted == \A r \in Replicas : up[r] /\ rstate[r].head # None

\* Eventually every replica has a non-empty history, and stays so.
Progress == <>[]AllAccepted
=============================================================================
