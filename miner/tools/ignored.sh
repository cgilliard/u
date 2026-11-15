#!/usr/bin/env bash
# No test is ignored and forgotten: every test marked #[ignore] is a
# benchmark, run by tools/bench.sh, or has a job of its own in
# .github/workflows/test.yml. This checks that each is named in one of
# the two, and that neither names a test there is not.
#
# The tests listed are those ignored in a release build: a test ignored
# only in debug builds (too slow there) runs in the release job.
set -euo pipefail
cd "$(dirname "$0")/.."

workflow=../.github/workflows/test.yml
ignored=$(cargo test --locked --release --features dev --lib -- --list --ignored 2>/dev/null | sed -n 's/: test$//p')
[ -n "$ignored" ] || { echo "no ignored test was listed: the listing failed" >&2; exit 1; }

status=0
for t in $ignored; do
    if ! grep -qE "^ +$t\$" tools/bench.sh && ! grep -qE "^ +- $t\$" "$workflow"; then
        echo "ignored and run nowhere: $t" >&2
        status=1
    fi
done
# And the other way: a name in either list is a test that is ignored.
named=$( { sed -n '/^BENCHES=(/,/^)/p' tools/bench.sh | sed -n 's/^ \+\([a-z0-9_:]\+\)$/\1/p'
           sed -n '/# slow-tests:begin/,/# slow-tests:end/p' "$workflow" | sed -n 's/^ \+- \([a-z0-9_:]\+\)$/\1/p'; } )
for t in $named; do
    if ! echo "$ignored" | grep -qx "$t"; then
        echo "named, and no ignored test: $t" >&2
        status=1
    fi
done
[ $status -eq 0 ] && echo "every ignored test is run: $(echo "$ignored" | wc -l) of them"
exit $status
