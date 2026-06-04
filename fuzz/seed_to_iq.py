#!/usr/bin/env python3
"""Convert afl_lora_rx_harness seeds into replayable IQ files."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


def parse_seed(seed: bytes) -> tuple[int, int, bytes]:
    if len(seed) < 2:
        raise ValueError("seed must contain at least two bytes")
    return seed[0], seed[1], seed[2:]


def seed_config(cfg: int) -> dict[str, int | bool]:
    return {
        "sf": 7 + (cfg & 0x03),
        "cr": 1 + ((cfg >> 2) & 0x03),
        "has_crc": bool((cfg >> 4) & 0x01),
        "implicit_header": bool((cfg >> 5) & 0x01),
    }


def cs8_to_fc32(iq: bytes) -> bytes:
    out = bytearray()
    for idx in range(0, len(iq) - 1, 2):
        i_sample = struct.unpack("b", iq[idx:idx + 1])[0] / 128.0
        q_sample = struct.unpack("b", iq[idx + 1:idx + 2])[0] / 128.0
        out.extend(struct.pack("<ff", i_sample, q_sample))
    return bytes(out)


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert AFL LoRa RX seed to raw IQ")
    parser.add_argument("seed", type=Path)
    parser.add_argument("--cs8-out", type=Path, help="write signed int8 interleaved IQ")
    parser.add_argument("--fc32-out", type=Path, help="write GNU Radio complex64/fc32 IQ")
    parser.add_argument("--sample-rate", type=int, default=500000)
    args = parser.parse_args()

    seed = args.seed.read_bytes()
    cfg, pay_len, iq = parse_seed(seed)
    info = seed_config(cfg)
    samples = len(iq) // 2
    duration_s = samples / args.sample_rate

    print(f"seed: {args.seed}")
    print(f"cfg: 0x{cfg:02x} ({info})")
    print(f"payload_len_hint: {pay_len}")
    print(f"iq_format: cs8 interleaved")
    print(f"samples: {samples}")
    print(f"sample_rate: {args.sample_rate}")
    print(f"duration_s: {duration_s:.6f}")

    if args.cs8_out:
        args.cs8_out.parent.mkdir(parents=True, exist_ok=True)
        args.cs8_out.write_bytes(iq)
        print(f"wrote cs8: {args.cs8_out}")

    if args.fc32_out:
        args.fc32_out.parent.mkdir(parents=True, exist_ok=True)
        args.fc32_out.write_bytes(cs8_to_fc32(iq))
        print(f"wrote fc32: {args.fc32_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
