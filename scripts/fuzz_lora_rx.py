#!/usr/bin/env python3
"""Fuzz the gr-lora_sdr hierarchical LoRa RX block with byte payloads.

The harness builds a TX -> channel_model -> RX flowgraph per case, injects a
random PMT u8vector payload into the TX message port, and compares the payload
received from the RX "bytes" message port.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import pmt
from gnuradio import blocks, channels, gr

lora_sdr = None


DEFAULT_BW = 125_000
DEFAULT_CENTER_FREQ = 868_100_000
DEFAULT_SYNC_WORD = [0x12]


@dataclass
class FuzzCase:
    index: int
    seed: int
    sf: int
    cr: int
    has_crc: bool
    impl_head: bool
    payload_len: int
    samp_rate: int
    bw: int
    snr_db: float | None
    clk_offset_ppm: float
    payload_hex: str


@dataclass
class FuzzResult:
    case: FuzzCase
    ok: bool
    elapsed_s: float
    received_hex: str | None
    error: str | None = None


def bytes_to_pmt(payload: bytes) -> pmt.pmt_t:
    return pmt.init_u8vector(len(payload), list(payload))


def import_lora_sdr() -> None:
    global lora_sdr
    try:
        import gnuradio.lora_sdr as imported_lora_sdr
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "Could not import gnuradio.lora_sdr. Build and install the OOT module, "
            "or source the generated setup_env.sh before running this fuzzer."
        ) from exc
    lora_sdr = imported_lora_sdr


def pmt_to_bytes(message: pmt.pmt_t) -> bytes:
    payload = pmt.cdr(message) if pmt.is_pair(message) else message
    if pmt.is_u8vector(payload):
        return bytes(pmt.u8vector_elements(payload))
    if pmt.is_symbol(payload):
        return pmt.symbol_to_string(payload).encode("latin-1")
    raise TypeError(f"unsupported RX message PMT type: {payload}")


def random_payload(rng: random.Random, length: int, pattern: str) -> bytes:
    if pattern == "random":
        return bytes(rng.randrange(0, 256) for _ in range(length))
    if pattern == "zeros":
        return bytes(length)
    if pattern == "ones":
        return bytes([0xFF]) * length
    if pattern == "counter":
        return bytes(i & 0xFF for i in range(length))
    if pattern == "edge":
        edge = [0x00, 0xFF, 0x55, 0xAA, 0x7F, 0x80]
        return bytes(edge[i % len(edge)] for i in range(length))
    raise ValueError(f"unknown payload pattern: {pattern}")


def make_case(args: argparse.Namespace, index: int, rng: random.Random) -> FuzzCase:
    sf = rng.choice(args.sf)
    cr = rng.choice(args.cr)
    has_crc = rng.choice(args.crc)
    impl_head = rng.choice(args.implicit_header)

    min_len = 2 if has_crc else 1
    max_len = min(args.max_len, 255)
    payload_len = rng.randint(min_len, max(min_len, max_len))
    payload = random_payload(rng, payload_len, rng.choice(args.pattern))

    bw = rng.choice(args.bw)
    samp_rate = bw * args.oversampling

    return FuzzCase(
        index=index,
        seed=args.seed,
        sf=sf,
        cr=cr,
        has_crc=has_crc,
        impl_head=impl_head,
        payload_len=payload_len,
        samp_rate=samp_rate,
        bw=bw,
        snr_db=args.snr_db,
        clk_offset_ppm=args.clk_offset_ppm,
        payload_hex=payload.hex(),
    )


class RxFuzzFlowgraph(gr.top_block):
    def __init__(self, case: FuzzCase, payload: bytes, zero_padding_symbols: int):
        super().__init__("lora_rx_fuzz", catch_exceptions=True)

        os_factor = int(case.samp_rate / case.bw)
        frame_zero_padd = int(zero_padding_symbols * (2**case.sf) * os_factor)
        noise_voltage = 0.0
        if case.snr_db is not None:
            noise_voltage = 10 ** (-case.snr_db / 20)

        self.tx = lora_sdr.lora_sdr_lora_tx(
            bw=case.bw,
            cr=case.cr,
            has_crc=case.has_crc,
            impl_head=case.impl_head,
            samp_rate=case.samp_rate,
            sf=case.sf,
            ldro_mode=2,
            frame_zero_padd=frame_zero_padd,
            sync_word=DEFAULT_SYNC_WORD,
        )
        self.channel = channels.channel_model(
            noise_voltage=noise_voltage,
            frequency_offset=(DEFAULT_CENTER_FREQ * case.clk_offset_ppm * 1e-6 / case.samp_rate),
            epsilon=(1.0 + case.clk_offset_ppm * 1e-6),
            taps=[1.0 + 0.0j],
            noise_seed=case.seed + case.index,
            block_tags=True,
        )
        self.rx = lora_sdr.lora_sdr_lora_rx(
            center_freq=DEFAULT_CENTER_FREQ,
            bw=case.bw,
            cr=case.cr,
            has_crc=case.has_crc,
            impl_head=case.impl_head,
            pay_len=case.payload_len,
            samp_rate=case.samp_rate,
            sf=case.sf,
            sync_word=DEFAULT_SYNC_WORD,
            soft_decoding=False,
            ldro_mode=2,
            print_rx=[False, False],
        )
        self.rx_sink = blocks.null_sink(gr.sizeof_char)
        self.msg_debug = blocks.message_debug()
        self.strobe = blocks.message_strobe(bytes_to_pmt(payload), 100)

        self.msg_connect((self.strobe, "strobe"), (self.tx, "in"))
        self.msg_connect((self.rx, "bytes"), (self.msg_debug, "store"))
        self.connect((self.tx, 0), (self.channel, 0))
        self.connect((self.channel, 0), (self.rx, 0))
        self.connect((self.rx, 0), (self.rx_sink, 0))


def run_case(args: argparse.Namespace, case: FuzzCase) -> FuzzResult:
    payload = bytes.fromhex(case.payload_hex)
    tb = RxFuzzFlowgraph(case, payload, args.zero_padding_symbols)
    start = time.monotonic()
    received: bytes | None = None
    error: str | None = None

    try:
        tb.start()
        deadline = start + args.timeout
        while time.monotonic() < deadline:
            if tb.msg_debug.num_messages() > 0:
                received = pmt_to_bytes(tb.msg_debug.get_message(0))
                break
            time.sleep(0.02)
    except Exception as exc:  # GNU Radio exceptions can cross from C++ here.
        error = repr(exc)
    finally:
        tb.stop()
        tb.wait()

    elapsed = time.monotonic() - start
    if received is None and error is None:
        error = f"timeout after {args.timeout:.2f}s"

    return FuzzResult(
        case=case,
        ok=(received == payload),
        elapsed_s=elapsed,
        received_hex=received.hex() if received is not None else None,
        error=error,
    )


def parse_csv_ints(value: str) -> list[int]:
    return [int(item, 0) for item in value.split(",") if item.strip()]


def parse_csv_bools(value: str) -> list[bool]:
    mapping = {
        "1": True,
        "true": True,
        "yes": True,
        "0": False,
        "false": False,
        "no": False,
    }
    parsed = []
    for item in value.split(","):
        key = item.strip().lower()
        if key:
            parsed.append(mapping[key])
    if not parsed:
        raise argparse.ArgumentTypeError("expected at least one boolean value")
    return parsed


def write_json_report(path: Path, results: list[FuzzResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data: list[dict[str, Any]] = [asdict(result) for result in results]
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fuzz the gr-lora_sdr LoRa RX block")
    parser.add_argument("-n", "--cases", type=int, default=25, help="number of fuzz cases")
    parser.add_argument("--seed", type=int, default=0x10A, help="reproducible RNG seed")
    parser.add_argument("--timeout", type=float, default=4.0, help="seconds to wait per case")
    parser.add_argument("--max-len", type=int, default=64, help="maximum payload bytes")
    parser.add_argument("--sf", type=parse_csv_ints, default=parse_csv_ints("7"), help="comma-separated SF values")
    parser.add_argument("--cr", type=parse_csv_ints, default=parse_csv_ints("1,2,3,4"), help="comma-separated CR values")
    parser.add_argument("--crc", type=parse_csv_bools, default=parse_csv_bools("true,false"), help="comma-separated CRC booleans")
    parser.add_argument("--implicit-header", type=parse_csv_bools, default=parse_csv_bools("false,true"), help="comma-separated implicit header booleans")
    parser.add_argument("--bw", type=parse_csv_ints, default=parse_csv_ints("125000"), help="comma-separated bandwidth values")
    parser.add_argument("--oversampling", type=int, default=4, help="sample-rate multiplier over bandwidth")
    parser.add_argument("--snr-db", type=float, default=None, help="optional channel SNR in dB")
    parser.add_argument("--clk-offset-ppm", type=float, default=0.0, help="optional clock offset in ppm")
    parser.add_argument("--zero-padding-symbols", type=int, default=10, help="TX zero padding after each frame")
    parser.add_argument(
        "--pattern",
        action="append",
        choices=["random", "zeros", "ones", "counter", "edge"],
        default=None,
        help="payload pattern pool; can be repeated",
    )
    parser.add_argument("--json-report", type=Path, help="write per-case JSON results")
    parser.add_argument("--fail-fast", action="store_true", help="stop at the first mismatch or timeout")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.pattern is None:
        args.pattern = ["random", "edge"]

    import_lora_sdr()

    rng = random.Random(args.seed)
    results: list[FuzzResult] = []
    failures = 0

    print(f"[*] LoRa RX fuzzing: cases={args.cases} seed={args.seed}")
    for index in range(args.cases):
        case = make_case(args, index, rng)
        result = run_case(args, case)
        results.append(result)
        failures += 0 if result.ok else 1

        status = "OK" if result.ok else "FAIL"
        print(
            f"[{status}] #{case.index:04d} sf={case.sf} cr={case.cr} "
            f"crc={int(case.has_crc)} implicit={int(case.impl_head)} "
            f"len={case.payload_len} elapsed={result.elapsed_s:.2f}s"
        )
        if not result.ok:
            print(f"      tx={case.payload_hex}")
            print(f"      rx={result.received_hex}")
            print(f"      error={result.error}")
            if args.fail_fast:
                break

    if args.json_report:
        write_json_report(args.json_report, results)
        print(f"[*] JSON report written to {args.json_report}")

    passed = len(results) - failures
    print(f"[*] Summary: passed={passed} failed={failures} total={len(results)}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
