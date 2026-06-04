#!/usr/bin/env python3
"""Generate deterministic IQ seed files for the AFL++ LoRa RX harness."""

from __future__ import annotations

import argparse
import math
import random
from pathlib import Path


def clamp_i8(value: float) -> int:
    return max(-128, min(127, int(round(value))))


def encode_iq(samples: list[complex]) -> bytes:
    out = bytearray()
    for sample in samples:
        out.append(clamp_i8(sample.real * 127) & 0xFF)
        out.append(clamp_i8(sample.imag * 127) & 0xFF)
    return bytes(out)


def tone(num_samples: int, cycles: float, phase: float = 0.0) -> list[complex]:
    samples = []
    for idx in range(num_samples):
        angle = 2.0 * math.pi * cycles * idx / max(1, num_samples) + phase
        samples.append(complex(math.cos(angle), math.sin(angle)))
    return samples


def chirp(num_samples: int, start_cycles: float, end_cycles: float) -> list[complex]:
    samples = []
    span = end_cycles - start_cycles
    for idx in range(num_samples):
        x = idx / max(1, num_samples - 1)
        cycles = start_cycles + span * x
        angle = 2.0 * math.pi * cycles * x
        samples.append(complex(math.cos(angle), math.sin(angle)))
    return samples


def noise(num_samples: int, rng: random.Random) -> list[complex]:
    return [
        complex(rng.uniform(-1.0, 1.0), rng.uniform(-1.0, 1.0))
        for _ in range(num_samples)
    ]


def alternating(num_samples: int) -> list[complex]:
    values = [complex(1.0, 0.0), complex(0.0, 1.0), complex(-1.0, 0.0), complex(0.0, -1.0)]
    return [values[idx % len(values)] for idx in range(num_samples)]


def seed_prefix(sf: int, cr: int, has_crc: bool, implicit_header: bool, payload_len: int) -> bytes:
    cfg = ((sf - 7) & 0x03) | (((cr - 1) & 0x03) << 2)
    cfg |= (1 << 4) if has_crc else 0
    cfg |= (1 << 5) if implicit_header else 0
    return bytes([cfg, payload_len & 0xFF])


def write_seed(path: Path, prefix: bytes, samples: list[complex]) -> None:
    path.write_bytes(prefix + encode_iq(samples))


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AFL++ IQ seeds for afl_lora_rx_harness")
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("fuzz/corpus_iq"))
    parser.add_argument("--seed", type=int, default=0x10A)
    parser.add_argument("--sf", type=int, default=7)
    parser.add_argument("--cr", type=int, default=1)
    parser.add_argument("--payload-len", type=int, default=16)
    parser.add_argument("--symbols", type=int, default=24)
    parser.add_argument("--oversampling", type=int, default=4)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    samples_per_symbol = (2**args.sf) * args.oversampling
    total_samples = samples_per_symbol * args.symbols

    configs = [
        ("explicit_crc", seed_prefix(args.sf, args.cr, True, False, args.payload_len)),
        ("implicit_crc", seed_prefix(args.sf, args.cr, True, True, args.payload_len)),
        ("explicit_nocrc", seed_prefix(args.sf, args.cr, False, False, args.payload_len)),
    ]
    waveforms = [
        ("tone_low", tone(total_samples, 2.0)),
        ("tone_high", tone(total_samples, 32.0, phase=0.5)),
        ("chirp_up", chirp(total_samples, 0.0, 96.0)),
        ("chirp_down", chirp(total_samples, 96.0, 0.0)),
        ("noise", noise(total_samples, rng)),
        ("alternating", alternating(total_samples)),
    ]

    count = 0
    for config_name, prefix in configs:
        for waveform_name, samples in waveforms:
            write_seed(args.output_dir / f"{config_name}_{waveform_name}.seed", prefix, samples)
            count += 1

    print(f"wrote {count} seeds to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
