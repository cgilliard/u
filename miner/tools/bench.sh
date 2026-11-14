#!/usr/bin/env bash
# The benchmarks: the timing tests marked #[ignore], built with --release
# and run one at a time so that none competes with another. Writes under
# target/bench:
#
#   bench.txt    what each printed, headed by the commit, compiler and CPU
#   summary.md   the same in a code block, for the CI run's page
#
# A timing test is added to BENCHES below by name: other ignored tests
# (slow ones, say) are not benchmarks and are not run here.
#
# The figures depend on the machine. Compare runs on the same one only;
# CI runners are shared and vary from run to run.
set -euo pipefail
cd "$(dirname "$0")/.."

BENCHES=(
    poseidon2::bench::permutation_throughput
    poseidon2::batch_tests::batch_throughput
    poseidon2::speed::compress_speed
)

out=target/bench
mkdir -p "$out"

cargo test --locked --release --lib --no-run
# A test's own output is on both streams; cargo's progress is not wanted.
cargo test --locked --release --lib -- --ignored --exact --nocapture --test-threads=1 "${BENCHES[@]}" \
    > "$out/raw.txt" 2>&1 || { cat "$out/raw.txt"; exit 1; }

ran=$(grep -c '^test .* \.\.\. ' "$out/raw.txt" || true)
if [ "$ran" -ne "${#BENCHES[@]}" ]; then
    cat "$out/raw.txt"
    echo "expected ${#BENCHES[@]} benchmarks, ran $ran: a name in BENCHES matches no test" >&2
    exit 1
fi

commit=$(git rev-parse --short HEAD 2>/dev/null || echo "no commit")
if [ -r /proc/cpuinfo ]; then
    cpu=$(sed -n 's/^model name[^:]*: *//p' /proc/cpuinfo | head -1)
    cores=$(grep -c '^processor' /proc/cpuinfo)
else
    cpu=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown CPU")
    cores=$(sysctl -n hw.ncpu 2>/dev/null || echo "?")
fi

{
    echo "Benchmarks ($commit)"
    echo "$(rustc --version), $(rustc -vV | sed -n 's/^host: //p')"
    echo "${cpu:-unknown CPU}, $cores cores"
    # "test NAME ... first line", more lines, then "ok" on a line of its own.
    awk '
        /^test .* \.\.\. / {
            name = $2
            sub(/^test [^ ]+ \.\.\. /, "")
            print "\n" name
            if ($0 != "" && $0 != "ok") print "  " $0
            inside = 1
            next
        }
        inside && $0 == "ok" { inside = 0; next }
        inside && $0 != "" { print "  " $0 }
    ' "$out/raw.txt"
} > "$out/bench.txt"

{
    printf '## Benchmarks\n\n```text\n'
    cat "$out/bench.txt"
    printf '```\n\nTimings on a shared CI runner vary from run to run: compare like with like.\n'
} > "$out/summary.md"

cat "$out/bench.txt"
