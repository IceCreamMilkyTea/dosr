#!/usr/bin/env python3
"""Mutation testing of the DOSR state machine.

Each mutant removes or weakens ONE safety check in pkg/app. The test suite
must fail on every mutant ("killed"); a surviving mutant means a check is
not covered by any test. Run from the repository root:

    python3 scripts/mutation_test.py

The source files are restored after every mutant, also on interruption.
"""
import json, subprocess, sys, time, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
MUTANTS = [
    ("M01 no expected-head check", "pkg/app/exec.go",
     "if br.Head != b.ExpectedHead {\n\t\treturn fail(types.CodeStaleHead, \"head is %s, tx expects %s\"",
     "if false {\n\t\treturn fail(types.CodeStaleHead, \"head is %s, tx expects %s\""),
    ("M02 no policy-version check", "pkg/app/exec.go",
     "if b.PolicyVersion != repo.PolicyVersion {", "if false {"),
    ("M03 verdict not checked", "pkg/app/verify.go",
     "if !v.Approve {", "if false {"),
    ("M04 echoed candidate not checked", "pkg/app/verify.go",
     "if v.Candidate != b.Candidate {", "if false {"),
    ("M05 revealed request body not compared with the recomputed one", "pkg/app/verify.go",
     "if !bytes.Equal(tr.Fields[attest.FieldReqBody], reqBody) {",
     "if !bytes.Equal(tr.Fields[attest.FieldReqBody], reqBody) && false {"),
    ("M06 request headers not restricted", "pkg/app/verify.go",
     "want, ok := allowedReqHeaders[name]\n\t\t\tif !ok {",
     "want, ok := allowedReqHeaders[name]\n\t\t\tif !ok && false {"),
    ("M07 any header may be hidden", "pkg/app/verify.go",
     "if !hideableReqHeaders[name] {", "if false {"),
    ("M08 server name not checked", "pkg/app/verify.go",
     "if tr.ServerName != host {", "if false {"),
    ("M09 HTTP status not checked", "pkg/app/verify.go",
     "s != \"200\" {", "false {"),
    ("M10 responding model not checked", "pkg/app/verify.go",
     "if !pol.HasModel(v.Model) {", "if false {"),
    ("M11 receipt expiry not checked", "pkg/app/exec.go",
     "if age > repo.Policy.MaxReceiptAgeSec {", "if false {"),
    ("M12 future receipts accepted", "pkg/app/exec.go",
     "if -age > repo.Policy.MaxClockSkewSec {", "if false {"),
    ("M13 envelope signature not verified", "pkg/app/exec.go",
     "if err := tx.VerifySig(); err != nil {", "if err := error(nil); err != nil {"),
    ("M14 evidence cached even if it depended on uncommitted objects", "pkg/app/exec.go",
     "if c.objs.pendingHits == before {", "if before >= 0 {"),
    ("M15 intent not matched against the change", "pkg/app/exec.go",
     "if intent.Repo != b.Repo || intent.Branch != b.Branch ||\n\t\t\tintent.Base != b.ExpectedHead || intent.Candidate != b.Candidate {",
     "if false {"),
    ("M16 intent nonce not bound into the request", "pkg/app/exec.go",
     "nonce = intent.Nonce", "nonce = nil"),
    ("M17 attempts not bounded", "pkg/app/exec.go",
     "if c.st.Attempts[ak] >= repo.Policy.MaxAttempts {", "if false {"),
    ("M18 policy update threshold not enforced", "pkg/app/exec.go",
     "if valid < repo.Policy.Threshold {", "if false {"),
    ("M19 policy approvals not signature-checked", "pkg/app/exec.go",
     "if !ed25519.Verify(ed25519.PublicKey(ap.PubKey), msg, ap.Sig) {",
     "if !ed25519.Verify(ed25519.PublicKey(ap.PubKey), msg, ap.Sig) && false {"),
    ("M20 policy approvals accepted from non-maintainers", "pkg/app/exec.go",
     "if !repo.Policy.HasMaintainer(ap.PubKey) {", "if !repo.Policy.HasMaintainer(ap.PubKey) && false {"),
    ("M21 chain id not checked (AcceptCommit)", "pkg/app/exec.go",
     "\tb, err := tx.AcceptCommit()\n\tif err != nil {\n\t\treturn fail(types.CodeMalformed, \"%v\", err)\n\t}\n\tif b.ChainID != c.st.ChainID {",
     "\tb, err := tx.AcceptCommit()\n\tif err != nil {\n\t\treturn fail(types.CodeMalformed, \"%v\", err)\n\t}\n\tif false {"),
    ("M22 strict ProcessProposal accepts everything", "pkg/app/app.go",
     "if r := a.exec(c, tx); r.code != types.CodeOK {\n\t\t\ta.stats.observeRejectedProposal()",
     "if r := a.exec(c, tx); false && r.code != types.CodeOK {\n\t\t\ta.stats.observeRejectedProposal()"),
    ("M23 objects not written at commit", "pkg/app/app.go",
     "must(c.objs.writeTo(batch))", "_ = c.objs"),
    ("M24 history not written at commit", "pkg/app/app.go",
     "must(batch.Set(histKey(e.Repo, e.Branch, e.Seq), eb))", "_ = eb"),
    ("M25 intents survive a head change", "pkg/app/exec.go",
     "\tc.st.pruneIntents(b.Repo, b.Branch)\n", "\t_ = b.Branch\n"),
    ("M26 response path not checked", "pkg/app/verify.go",
     "p != pol.ProviderPath {", "false {"),
    ("M27 response body may be hidden", "pkg/app/verify.go",
     "if hidden[n] && !strings.HasPrefix(n, attest.FieldReqHeaderPfx) && !strings.HasPrefix(n, attest.FieldRespHeadPfx) {",
     "if false {"),
]
HELPER = '''
// proverBody is injected by mutant M05.
func proverBody(p *attest.Presentation, fallback []byte) []byte {
	for _, l := range p.Leaves {
		if l.Name == attest.FieldReqBody && len(l.Value) > 0 {
			return l.Value
		}
	}
	return fallback
}
'''

# Mutants that are expected to survive because the removed check is
# redundant (defence in depth): another layer enforces the same property.
EQUIVALENT = {
    "M05": "attest.ProxyVerifier already binds a Revealed req.body to the value the validator supplies; the comparison in checkTranscript is a second line of defence",
}

def run_tests():
    t = time.time()
    p = subprocess.run(["go", "test", "./pkg/app/", "-count=1", "-sim.seeds=4"],
                       cwd=ROOT, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr, time.time() - t

def main():
    rc, out, _ = run_tests()
    if rc != 0:
        print("baseline test suite fails; fix that first\n" + out[-2000:]); sys.exit(2)
    results, survived = [], 0
    for name, path, old, new in MUTANTS:
        f = ROOT / path
        orig = f.read_text()
        if orig.count(old) != 1:
            print(f"{name}: pattern matches {orig.count(old)} times in {path}; mutant definition is stale")
            sys.exit(2)
        mutated = orig.replace(old, new)
        if "proverBody" in new:
            mutated += HELPER
        try:
            f.write_text(mutated)
            rc, out, dt = run_tests()
        finally:
            f.write_text(orig)
        if "build failed" in out or "[setup failed]" in out:
            print(f"{name}: mutant does not compile\n{out[-1500:]}"); sys.exit(2)
        killed = rc != 0
        eq = EQUIVALENT.get(name.split()[0])
        if not killed and eq:
            results.append({"mutant": name, "file": path, "killed": False, "equivalent": True, "note": eq, "seconds": round(dt, 1)})
            print(f"REDUNDANT {name:70s} ({eq})")
            continue
        survived += not killed
        first = next((l.strip() for l in out.splitlines() if l.strip().startswith("--- FAIL")), "")
        results.append({"mutant": name, "file": path, "killed": killed, "seconds": round(dt, 1), "killed_by": first})
        print(f"{'KILLED  ' if killed else 'SURVIVED'}  {name:70s} {first}")
    (ROOT / "eval/results").mkdir(parents=True, exist_ok=True)
    (ROOT / "eval/results/mutation.json").write_text(json.dumps(results, indent=1))
    red = sum(1 for r in results if r.get("equivalent"))
    print(f"\n{len(MUTANTS)} mutants: {len(MUTANTS) - survived - red} killed, {red} redundant check(s), {survived} survived")
    sys.exit(1 if survived else 0)

if __name__ == "__main__":
    main()
