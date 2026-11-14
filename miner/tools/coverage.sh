#!/usr/bin/env bash
# Code coverage of the test suite, measured with the Rust toolchain's own
# LLVM tools (no cargo plugin): builds the tests instrumented, runs them,
# and writes under target/coverage:
#
#   report.txt   llvm-cov's table, per file (also printed)
#   summary.md   the same as a Markdown table, for the CI run's page
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

# Its own target directory: instrumented objects do not mix with ordinary ones.
export RUSTFLAGS="-C instrument-coverage"
export LLVM_PROFILE_FILE="$PWD/$out/prof/%p-%m.profraw"
cargo test --locked --target-dir "$out"

# The test binaries just run, as cargo names them.
objects=$(cargo test --locked --target-dir "$out" --no-run --message-format=json \
    | grep -o '"executable":"[^"]*"' | cut -d'"' -f4 | sed 's/^/--object=/')

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
awk '
    /^-+$/ || /^Filename/ || NF < 10 { next }
    {
        name = ($1 == "TOTAL") ? "**Total**" : "`" $1 "`"
        row = "| " name " | " $8 " | " $9 " | " $10 " | " $7 " | " $4 " |"
        if ($1 == "TOTAL") { total = row; lines = $10 } else { rows = rows row "\n" }
    }
    END {
        print "## Code coverage: " lines " of lines\n"
        print "| File | Lines | Missed | Line coverage | Function coverage | Region coverage |"
        print "|---|---:|---:|---:|---:|---:|"
        printf "%s", rows
        print total
        print "\nIncludes each file'"'"'s own tests. The annotated source is in the `coverage-html` artifact."
    }
' "$out/report.txt" > "$out/summary.md"

cat "$out/report.txt"
echo
echo "summary: $out/summary.md   annotated source: $out/html/index.html"
