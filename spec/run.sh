#!/usr/bin/env bash
# Runs every model-checking job of the DOSR specification and prints a
# PASS/FAIL table.
#
#   ./run.sh            run everything
#   ./run.sh PATTERN    run only the jobs whose name matches the regex; the
#                       rows of the other jobs in out/results.txt are kept
#
# Kinds of jobs
#   holds        TLC must explore the complete state space without error
#                (the .cfg files in this directory)
#   violates X   TLC must report that exactly X is violated: deliberately
#                false properties in expected/ and mutants in mutants/; the
#                counterexample is saved to traces/<job>.txt
#   equiv X      an EQUIVALENT mutant (mutants/ whose header says
#                "invariant X HOLDS"): TLC must complete without error
#
# Every job is bounded so that the whole table completes in well under an
# hour on 8 cores (each job < 5 min).  The hours-long original models live in
# large/ and are NOT run by this script (see large/README.md).  Each java
# invocation is killed after $TIMEOUT seconds (default 600) and reported as
# TIMEOUT; a TLC crash (e.g. disk full) is reported as CRASH.
#
# Environment: WORKERS (default: number of cores), HEAP (default 8g),
#              JAVA (default: java), TIMEOUT (seconds, default 600)
set -u
cd "$(dirname "$0")"
JAR=tools/tla2tools.jar
JAVA=${JAVA:-java}
WORKERS=${WORKERS:-$( (sysctl -n hw.ncpu || nproc) 2>/dev/null | head -1)}
HEAP=${HEAP:-8g}
TIMEOUT=${TIMEOUT:-600}
PATTERN=${1:-.}

if [ ! -f "$JAR" ]; then
    echo "downloading tla2tools.jar ..."
    mkdir -p tools
    curl -sL -o "$JAR" \
        https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar || exit 1
fi

# `timeout` is GNU coreutils; on macOS it may be called gtimeout.
if command -v timeout >/dev/null 2>&1; then TMO="timeout $TIMEOUT"
elif command -v gtimeout >/dev/null 2>&1; then TMO="gtimeout $TIMEOUT"
else echo "WARNING: no timeout(1) found, jobs are not time-limited" >&2; TMO=""; fi

# name | config | expectation
JOBS="
SafetyChain|SafetyChain.cfg|holds
SafetyAdversary|SafetyAdversary.cfg|holds
SafetyFull|SafetyFull.cfg|holds
Replicas|Replicas.cfg|holds
Intents|Intents.cfg|holds
IntentsNoGrinding|IntentsNoGrinding.cfg|holds
Liveness|Liveness.cfg|holds
LivenessByz|LivenessByz.cfg|holds
LivenessIntents|LivenessIntents.cfg|holds
"
for f in expected/*.cfg mutants/*.cfg; do
    inv=$(sed -En 's/.*EXPECTED: (invariant|property) ([A-Za-z]+) is violated.*/\2/p' "$f" | head -1)
    if [ -n "$inv" ]; then
        JOBS="$JOBS$(basename "$f" .cfg)|$f|violates $inv
"
        continue
    fi
    inv=$(sed -En 's/.*EXPECTED: invariant ([A-Za-z]+) HOLDS.*/\1/p' "$f" | head -1)
    if [ -n "$inv" ]; then
        JOBS="$JOBS$(basename "$f" .cfg)|$f|equiv $inv
"
    else
        echo "WARNING: $f has no EXPECTED line, skipped" >&2
    fi
done

mkdir -p out traces
RESULTS=out/results.txt
# With a PATTERN the rows of the jobs that are not re-run are kept.
OLD=$(mktemp); [ -f "$RESULTS" ] && cp "$RESULTS" "$OLD"
NEW=$(mktemp)
fmt="%-36s %-38s %-7s %12s %11s %6s %8s\n"
printf "$fmt" JOB EXPECTATION RESULT GENERATED DISTINCT DEPTH TIME
fail=0
while IFS='|' read -r name cfg expect; do
    [ -z "$name" ] && continue
    echo "$name" | grep -Eq "$PATTERN" || continue
    log=out/$name.out
    # Breadth-first search with ONE worker returns a shortest counterexample,
    # so the jobs that are expected to fail run single-threaded.
    case "$expect" in violates*) w=1 ;; *) w=$WORKERS ;; esac
    # TLC unpacks the standard modules into java.io.tmpdir: give every job
    # its own so that concurrent runs do not race on those files.
    tmp="$PWD/out/tmp/$name"; mkdir -p "$tmp"
    start=$(date +%s)
    $TMO "$JAVA" -XX:+UseParallelGC -Xmx$HEAP -Djava.io.tmpdir="$tmp" -cp "$JAR" tlc2.TLC \
        -workers "$w" -deadlock -difftrace \
        -metadir "out/states/$name" -config "$cfg" MC.tla > "$log" 2>&1
    rc=$?
    end=$(date +%s)
    rm -rf "out/states/$name" "$tmp"

    gen=$(sed -n 's/^\([0-9]*\) states generated, \([0-9]*\) distinct states found.*/\1/p' "$log" | tail -1)
    dis=$(sed -n 's/^\([0-9]*\) states generated, \([0-9]*\) distinct states found.*/\2/p' "$log" | tail -1)
    dep=$(sed -n 's/^The depth of the complete state graph search is \([0-9]*\).*/\1/p' "$log" | tail -1)
    violated=$(sed -n 's/^Error: Invariant \([A-Za-z]*\) is violated.*/\1/p' "$log" | head -1)
    if grep -q "^Error: Temporal properties were violated" "$log"; then violated="(temporal)"; fi
    anyerror=$(grep -c "^Error:" "$log")
    crashed=$(grep -c "^Error: TLC threw an unexpected exception" "$log")
    complete=$(grep -c "^Model checking completed. No error has been found." "$log")

    if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then res=TIMEOUT
    elif [ "$crashed" != 0 ]; then res=CRASH
    else
        case "$expect" in
        holds|equiv*)
            if [ "$complete" = 1 ] && [ "$anyerror" = 0 ]; then res=PASS; else res=FAIL; fi ;;
        violates*)
            want=${expect#violates }
            if [ -n "$want" ] && [ "$violated" = "$want" ]; then
                res=PASS
                # length of the counterexample = number of states in the trace
                dep=$(grep -c "^State [0-9]*:" "$log")
                { echo "# job: $name    config: $cfg"
                  echo "# TLC found the expected violation of $want."
                  echo "# Only the variables that change are printed (-difftrace)."
                  sed -n '/^Error: Invariant/,/^[0-9]* states generated/p' "$log"
                } > "traces/$name.txt"
            else res=FAIL; fi ;;
        esac
    fi
    [ "$res" = PASS ] || fail=1
    printf "$fmt" "$name" "$expect" "$res" "${gen:--}" "${dis:--}" "${dep:--}" "$((end-start))s" | tee -a "$NEW"
done <<EOF2
$JOBS
EOF2
# assemble results.txt in job order: new row if the job ran, else the old row
{ printf "$fmt" JOB EXPECTATION RESULT GENERATED DISTINCT DEPTH TIME
  while IFS='|' read -r name cfg expect; do
      [ -z "$name" ] && continue
      row=$(grep "^$name " "$NEW" | tail -1)
      [ -z "$row" ] && row=$(grep "^$name " "$OLD" 2>/dev/null | tail -1)
      [ -n "$row" ] && echo "$row"
  done <<EOF3
$JOBS
EOF3
} > "$RESULTS"
rm -f "$OLD" "$NEW"
echo
if [ $fail = 0 ]; then echo "ALL JOBS PASSED"; else echo "SOME JOBS FAILED (see out/<job>.out)"; fi
exit $fail
