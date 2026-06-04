#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <afl-crash-seed> [report-dir]" >&2
  exit 2
fi

CRASH_SEED="$1"
REPORT_DIR="${2:-fuzz/evidence}"
mkdir -p "$REPORT_DIR"

BASE="$(basename "$CRASH_SEED")"
MIN_SEED="$REPORT_DIR/${BASE}.min.seed"
AFL_LOG="$REPORT_DIR/${BASE}.afl.log"
ASAN_LOG="$REPORT_DIR/${BASE}.asan.log"
REPORT="$REPORT_DIR/${BASE}.report.md"

echo "[*] Reproducing with AFL harness: $CRASH_SEED"
set +e
LD_LIBRARY_PATH=build-afl/lib ./build-afl/afl_lora_rx_harness "$CRASH_SEED" >"$AFL_LOG" 2>&1
AFL_EXIT=$?
set -e
echo "[*] AFL harness exit code: $AFL_EXIT"

echo "[*] Minimizing crash seed"
AFL_NO_FORKSRV=1 AFL_SKIP_CPUFREQ=1 LD_LIBRARY_PATH=build-afl/lib afl-tmin \
  -t 5000+ \
  -i "$CRASH_SEED" \
  -o "$MIN_SEED" \
  -- ./build-afl/afl_lora_rx_harness @@ >/dev/null

echo "[*] Reproducing minimized seed with ASAN/UBSAN"
set +e
ASAN_SYMBOLIZER_PATH="$(command -v llvm-symbolizer || true)" \
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
LD_LIBRARY_PATH=build-asan/lib \
./build-asan/afl_lora_rx_harness_asan "$MIN_SEED" >"$ASAN_LOG" 2>&1
ASAN_EXIT=$?
set -e
echo "[*] ASAN harness exit code: $ASAN_EXIT"

SUMMARY="$(grep -m1 -E 'SUMMARY:|runtime error:' "$ASAN_LOG" || true)"
ERROR_LINE="$(grep -m1 -E 'ERROR: AddressSanitizer|runtime error:' "$ASAN_LOG" || true)"
SEED_SIZE="$(wc -c < "$CRASH_SEED" | tr -d ' ')"
MIN_SIZE="$(wc -c < "$MIN_SEED" | tr -d ' ')"
SHA256="$(sha256sum "$MIN_SEED" | awk '{print $1}')"

cat >"$REPORT" <<EOF
# LoRa RX Crash Evidence

## Summary

- Component: gr-lora_sdr RX chain
- Harness: fuzz/afl_lora_rx_harness.cc
- Original seed: $CRASH_SEED
- Minimized seed: $MIN_SEED
- Original size: $SEED_SIZE bytes
- Minimized size: $MIN_SIZE bytes
- Minimized SHA256: $SHA256
- AFL harness exit code: $AFL_EXIT
- ASAN harness exit code: $ASAN_EXIT

## ASAN Classification

\`\`\`text
$ERROR_LINE
$SUMMARY
\`\`\`

## Reproduction

\`\`\`bash
LD_LIBRARY_PATH=build-afl/lib ./build-afl/afl_lora_rx_harness "$MIN_SEED"
\`\`\`

ASAN/UBSAN:

\`\`\`bash
ASAN_SYMBOLIZER_PATH="\$(command -v llvm-symbolizer || true)" \\
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1 \\
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \\
LD_LIBRARY_PATH=build-asan/lib \\
./build-asan/afl_lora_rx_harness_asan "$MIN_SEED"
\`\`\`

## Exploitability Assessment

This is a denial-of-service proof of concept against the LoRa RX processing chain.
The minimized IQ seed drives the receiver into a crash under the RX harness.

Practical attacker requirement:

- Direct access to the IQ input stream, or
- Ability to transmit/replay a crafted RF waveform that produces equivalent IQ samples at the receiver.

Expected impact:

- Receiver process crash.
- Loss of packet reception until process restart.

Current evidence supports DoS exploitability. It does not demonstrate code execution.

## Full ASAN Log

See:

\`\`\`text
$ASAN_LOG
\`\`\`
EOF

echo "[+] Evidence written:"
echo "    minimized seed: $MIN_SEED"
echo "    AFL log:        $AFL_LOG"
echo "    ASAN log:       $ASAN_LOG"
echo "    report:         $REPORT"
