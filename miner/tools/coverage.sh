#!/usr/bin/env bash
# Code coverage of the test suite, measured with the Rust toolchain's own
# LLVM tools (no cargo plugin): builds the tests instrumented, runs them,
# and writes under target/coverage:
#
#   report.txt   llvm-cov's table, per file (also printed)
#   summary.txt  the same as a Markdown table with its columns lined up, to paste
#   summary.md   that table and a copy of it in a code block, for the CI run's page
#   html/        the source annotated line by line; open html/index.html
#
# Needs the llvm-tools component: rustup component add llvm-tools
#
# The figures include the tests' own code (the `mod tests` of each file),
# which always runs; test_util.rs, only ever test code, is left out.
set -euo pipefail
cd "$(dirname "$0")/.."

out=target/coverage
host=$(rustc -vV | sed -n 's/^host: //p')
bin="$(rustc --print sysroot)/lib/rustlib/$host/bin"
if [ ! -x "$bin/llvm-cov" ] || [ ! -x "$bin/llvm-profdata" ]; then
    echo "llvm-cov not found in the toolchain: run 'rustup component add llvm-tools'" >&2
    exit 1
fi

rm -rf "$out/prof" "$out/html"
mkdir -p "$out/prof"

# The code has two paths where it matters for speed: AVX2 (packed.rs and
# what uses it) and a portable one. A build has one or the other, so on
# x86-64 the tests run twice, built for this CPU and for the plainest
# x86-64, and a line counts as covered if either run reached it. Each
# build has its own target directory: instrumented objects do not mix
# with ordinary ones, nor the two with each other.
case "$host" in
    x86_64-*) variants="native x86-64" ;;
    *) variants="native" ;;
esac
export LLVM_PROFILE_FILE="$PWD/$out/prof/%p-%m.profraw"

# The tests are hash after hash, and an unoptimized, instrumented build of
# them is many times slower than a debug build: too slow for CI's runners.
# So this build is optimized, with debug assertions and overflow checks
# still on (the test profile's and its dependencies'), and the decoder
# fuzzers run a fraction of their iterations: they reach their lines in
# the first few hundred, and the test jobs run them in full.
export CARGO_PROFILE_TEST_OPT_LEVEL=2
export CARGO_PROFILE_DEV_OPT_LEVEL=2
export TABMINER_FUZZ_ITERS="${TABMINER_FUZZ_ITERS:-500}"
objects=""
for cpu in $variants; do
    export RUSTFLAGS="-C instrument-coverage -C target-cpu=$cpu"
    cargo test --locked --target-dir "$out/$cpu"
    # The test binaries just run, as cargo names them.
    objects="$objects $(cargo test --locked --target-dir "$out/$cpu" --no-run --message-format=json \
        | grep -o '"executable":"[^"]*"' | cut -d'"' -f4 | sed 's/^/--object=/' | tr '\n' ' ')"
done
unset RUSTFLAGS

"$bin/llvm-profdata" merge -sparse "$out"/prof/*.profraw -o "$out/coverage.profdata"

# Only this crate's code: not the dependencies', nor the standard library's.
ignore='(/\.cargo/|/rustc/|/test_util\.rs$)'
# shellcheck disable=SC2086
"$bin/llvm-cov" report --instr-profile="$out/coverage.profdata" $objects \
    --ignore-filename-regex="$ignore" > "$out/report.txt"
# shellcheck disable=SC2086
"$bin/llvm-cov" show --format=html --output-dir="$out/html" \
    --instr-profile="$out/coverage.profdata" $objects --ignore-filename-regex="$ignore" > /dev/null

# The table as Markdown. A row of the report is the file name, then for
# regions, functions, lines and branches: the count, the missed, the percent.
#
# summary.txt is the table for pasting elsewhere: Markdown with its columns
# lined up, so it reads as plain text and renders as a table where Markdown
# does. summary.md shows the table, then summary.txt in a code block, which
# GitHub gives a copy button.
commit=$(git rev-parse --short HEAD 2>/dev/null || echo "no commit")
awk -v commit="$commit" '
    /^-+$/ || /^Filename/ || NF < 10 { next }
    {
        n++
        cell[n, 1] = ($1 == "TOTAL") ? "Total" : $1
        cell[n, 2] = $8; cell[n, 3] = $9; cell[n, 4] = $10; cell[n, 5] = $7; cell[n, 6] = $4
        if ($1 == "TOTAL") lines = $10
    }
    END {
        split("File,Lines,Missed,Line coverage,Function coverage,Region coverage", head, ",")
        for (c = 1; c <= 6; c++) {
            width[c] = length(head[c])
            for (r = 1; r <= n; r++) if (length(cell[r, c]) > width[c]) width[c] = length(cell[r, c])
        }
        print "Code coverage: " lines " of lines (" commit ")\n"
        line = "|"; rule = "|"
        for (c = 1; c <= 6; c++) {
            line = line sprintf(c == 1 ? " %-*s |" : " %*s |", width[c], head[c])
            dashes = sprintf("%*s", width[c] + 1, ""); gsub(/ /, "-", dashes)
            rule = rule (c == 1 ? dashes "-|" : dashes ":|")
        }
        print line; print rule
        for (r = 1; r <= n; r++) {
            line = "|"
            for (c = 1; c <= 6; c++) line = line sprintf(c == 1 ? " %-*s |" : " %*s |", width[c], cell[r, c])
            print line
        }
    }
' "$out/report.txt" > "$out/summary.txt"

{
    sed -n '1s/^/## /p' "$out/summary.txt"
    sed '1d' "$out/summary.txt"
    printf '\nIncludes each file'"'"'s own tests. The annotated source is in the `coverage-html` artifact.\n'
    printf '\n### To paste elsewhere\n\n```text\n'
    cat "$out/summary.txt"
    printf '```\n'
} > "$out/summary.md"

cat "$out/report.txt"
echo
cat "$out/summary.txt"
echo
echo "to paste: $out/summary.txt   annotated source: $out/html/index.html"
