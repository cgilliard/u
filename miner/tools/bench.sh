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
# On x86-64 they run twice: built for this CPU (as .cargo/config.toml
# builds by default; AVX2 where the CPU has it) and built for the
# plainest x86-64, the portable code path.
#
# The figures depend on the machine. Compare runs on the same one only;
# CI runners are shared and vary from run to run.
set -euo pipefail
cd "$(dirname "$0")/.."

BENCHES=(
    poseidon2::bench::permutation_throughput
    poseidon2::batch_tests::batch_throughput
    poseidon2::speed::compress_speed
    pow::tests::mainnet_timing
    pow_air::tests::cost
)

out=target/bench
mkdir -p "$out"

host=$(rustc -vV | sed -n 's/^host: //p')
case "$host" in
    x86_64-*) variants="native x86-64" ;;
    *) variants="native" ;;
esac

commit=$(git rev-parse --short HEAD 2>/dev/null || echo "no commit")
if [ -r /proc/cpuinfo ]; then
    cpu_name=$(sed -n 's/^model name[^:]*: *//p' /proc/cpuinfo | head -1)
    cores=$(grep -c '^processor' /proc/cpuinfo)
else
    cpu_name=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown CPU")
    cores=$(sysctl -n hw.ncpu 2>/dev/null || echo "?")
fi

{
    echo "Benchmarks ($commit)"
    echo "$(rustc --version), $host"
    echo "${cpu_name:-unknown CPU}, $cores cores"
} > "$out/bench.txt"

for cpu in $variants; do
    export RUSTFLAGS="-C target-cpu=$cpu"
    if rustc --print cfg -C target-cpu="$cpu" | grep -q 'target_feature="avx2"'; then
        path="AVX2"
    else
        path="portable"
    fi
    cargo test --locked --release --lib --no-run --target-dir "$out/$cpu"
    # A test's own output is on both streams; cargo's progress is not wanted.
    cargo test --locked --release --lib --target-dir "$out/$cpu" -- \
        --ignored --exact --nocapture --test-threads=1 "${BENCHES[@]}" \
        > "$out/raw-$cpu.txt" 2>&1 || { cat "$out/raw-$cpu.txt"; exit 1; }

    ran=$(grep -c '^test .* \.\.\. ' "$out/raw-$cpu.txt" || true)
    if [ "$ran" -ne "${#BENCHES[@]}" ]; then
        cat "$out/raw-$cpu.txt"
        echo "expected ${#BENCHES[@]} benchmarks, ran $ran: a name in BENCHES matches no test" >&2
        exit 1
    fi

    {
        printf '\n== built with target-cpu=%s: the %s path\n' "$cpu" "$path"
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
        ' "$out/raw-$cpu.txt"
    } >> "$out/bench.txt"
done
unset RUSTFLAGS

{
    printf '## Benchmarks\n\n```text\n'
    cat "$out/bench.txt"
    printf '```\n\nTimings on a shared CI runner vary from run to run: compare like with like.\n'
} > "$out/summary.md"

cat "$out/bench.txt"
