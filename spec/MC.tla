--------------------------------- MODULE MC ---------------------------------
(***************************************************************************)
(* Model-checking harness for DOSR: concrete commit forests, guard sets    *)
(* for the mutants, and the symmetry set.  The .cfg files pick from here.  *)
(***************************************************************************)
EXTENDS DOSR

\* ---- commit forests ------------------------------------------------------
\*
\*   Forest5:   none -+- a -+- c --- e        chain a,c,e (length 3)
\*                    |     `- d              siblings c,d (parent a)
\*                    `- b                    siblings a,b (parent none)
\*
Commits5 == {"a", "b", "c", "d", "e"}
Forest5  == [x \in Commits5 |->
               CASE x = "a" -> "none" [] x = "b" -> "none"
                 [] x = "c" -> "a"    [] x = "d" -> "a"
                 [] x = "e" -> "c"]

\*   Forest4:   none -+- a --- c --- d        chain a,c,d (length 3)
\*                    `- b                    siblings a,b
Commits4 == {"a", "b", "c", "d"}
Forest4  == [x \in Commits4 |->
               CASE x = "a" -> "none" [] x = "b" -> "none"
                 [] x = "c" -> "a"    [] x = "d" -> "c"]

\*   Forest3:   none -+- a --- c
\*                    `- b
Commits3 == {"a", "b", "c"}
Forest3  == [x \in Commits3 |->
               CASE x = "a" -> "none" [] x = "b" -> "none" [] x = "c" -> "a"]

\*   Forest2:   none -+- a
\*                    `- b
Commits2 == {"a", "b"}
Forest2  == [x \in Commits2 |-> "none"]

\* ---- guard sets ----------------------------------------------------------
Without(g) == AllGuards \ {g}

G_All            == AllGuards
G_NoHead         == Without("head")
G_NoMember       == Without("member")
G_NoVerdict      == Without("verdict")
G_NoBase         == Without("base")
G_NoCandidate    == Without("candidate")
G_NoPolicy       == Without("policy")
G_NoParent       == Without("parent")
G_NoVersion      == Without("version")
G_NoAuth         == Without("auth")
G_NoIntent       == Without("intent")
G_NoIntentUnused == Without("intentUnused")
G_NoAttemptCap   == Without("attemptCap")
G_NoNotaryIntent == Without("notaryIntent")
G_NoNotaryOnce   == Without("notaryOnce")
G_NoRestartIndex == Without("restartIndex")

\* Double mutants.  "intent" and "intentUnused" are EQUIVALENT single
\* mutants: with all other guards present, the notary's own intent check
\* ("notaryIntent") and the head check ("head") already imply them (see
\* README, "Equivalent mutants").  Removing the guard that makes them
\* redundant as well shows that they are load-bearing on their own.
G_NoIntent_NoNotaryIntent == AllGuards \ {"intent", "notaryIntent"}
G_NoIntentUnused_NoHead   == AllGuards \ {"intentUnused", "head"}

\* ---- symmetry ------------------------------------------------------------
\* Replicas are interchangeable.  Only used when checking invariants.
ReplicaSymmetry == Permutations(Replicas)
=============================================================================
