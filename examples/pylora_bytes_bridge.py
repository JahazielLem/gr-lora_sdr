#!/usr/bin/env python3

# Author: Kevin Leon
# Date: 2026

import argparse
import select
import signal
import socket
import string
import struct
import sys
import threading
import time

import pmt
import zmq

try:
  from bridge import bridge
except ImportError:
  bridge = None


DEFAULT_PLUTO_SOURCE = "ip:pluto.local"
DEFAULT_DOWNLINK_ADDRESS = "tcp://127.0.0.1:5009"
DEFAULT_UPLINK_ADDRESS = "tcp://127.0.0.1:5007"
DEFAULT_BRIDGE_HOST = "127.0.0.1"
DEFAULT_BRIDGE_PORT = 5008

DOWNLINK_FREQ = 916000000
DOWNLINK_BW = 250000
DOWNLINK_SF = 7

PCAP_GLOBAL_HEADER_FORMAT = "<LHHIILL"
PCAP_PACKET_HEADER_FORMAT = "<llll"
PCAP_MAGIC_NUMBER = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_MAX_PACKET_SIZE = 0x0000FFFF


def bytes_to_pmt_message(data: bytes):
  return pmt.init_u8vector(len(data), list(data))


def serialize_bytes(data: bytes) -> bytes:
  return pmt.serialize_str(bytes_to_pmt_message(data))


def pmt_message_to_bytes(message) -> bytes:
  payload = pmt.cdr(message) if pmt.is_pair(message) else message

  if pmt.is_u8vector(payload):
    return bytes(pmt.u8vector_elements(payload))

  if pmt.is_symbol(payload):
    return pmt.symbol_to_string(payload).encode("latin-1")

  if pmt.is_blob(payload):
    blob = pmt.blob_data(payload)
    return bytes(blob)

  raise TypeError(f"Unsupported PMT payload type: {payload}")


def zmq_frame_to_bytes(frame: bytes) -> bytes:
  try:
    return pmt_message_to_bytes(pmt.deserialize_str(frame))
  except Exception:
    return frame


def pcap_header(interface=148):
  return struct.pack(
    PCAP_GLOBAL_HEADER_FORMAT,
    PCAP_MAGIC_NUMBER,
    PCAP_VERSION_MAJOR,
    PCAP_VERSION_MINOR,
    0,
    0,
    PCAP_MAX_PACKET_SIZE,
    interface,
  )


class Pcap:
  def __init__(self, packet: bytes, timestamp_seconds: float):
    self.packet = packet
    self.timestamp_seconds = timestamp_seconds
    self.pcap_packet = self.pack()

  def pack(self):
    int_timestamp = int(self.timestamp_seconds)
    timestamp_offset = int((self.timestamp_seconds - int_timestamp) * 1_000_000)
    return (
      struct.pack(
        PCAP_PACKET_HEADER_FORMAT,
        int_timestamp,
        timestamp_offset,
        len(self.packet),
        len(self.packet),
      )
      + self.packet
    )

  def get(self):
    return self.pcap_packet


def hexdump(data: bytes, width: int = 16) -> str:
  lines = []
  for offset in range(0, len(data), width):
    chunk = data[offset:offset + width]
    hex_bytes = " ".join(f"{b:02X}" for b in chunk)
    hex_bytes = hex_bytes.ljust(width * 3)
    ascii_bytes = "".join(
      chr(b) if chr(b) in string.printable and b >= 0x20 else "."
      for b in chunk
    )
    lines.append(f"{offset:08X}  {hex_bytes}  {ascii_bytes}")
  return "\n".join(lines)


def show_args_config(args):
  print("========== Configuration ==========")
  for k, v in vars(args).items():
    print(f"{k:25}: {v}")
  print("----------------------------------\n")


class Controller:
  def __init__(self, args):
    self.args = args
    self.rxctx = None
    self.rxsock = None
    self.txctx = None
    self.txsock = None
    self.tb = None
    self.running = False
    self.f_output = None
    self.f_pcap_output = None
    self.bridge_sock = None
    self.last_reconnect_time = 0

  def file_write_frame(self, data: bytes):
    if self.f_output is not None:
      ts = time.time_ns()
      header = struct.pack("<QH", ts, len(data))
      self.f_output.write(header)
      self.f_output.write(data)
      self.f_output.flush()

  def file_open(self):
    self.f_output = open(self.args.output_file, "wb")

  def file_close(self):
    if self.f_output:
      self.f_output.close()

  def pcap_write_frame(self, data: bytes):
    if self.f_pcap_output is not None:
      self.f_pcap_output.write(Pcap(data, time.time()).get())
      self.f_pcap_output.flush()

  def pcap_open(self):
    self.f_pcap_output = open(self.args.pcap_output_file, "wb")
    self.f_pcap_output.write(pcap_header())
    self.f_pcap_output.flush()

  def pcap_close(self):
    if self.f_pcap_output:
      self.f_pcap_output.close()

  def setup(self):
    if bridge is not None:
      self.tb = bridge()
      self.tb.set_frequency(float(self.args.frequency))
      self.tb.set_bandwidth(int(self.args.bandwidth))
      self.tb.set_zmq_address(self.args.downlink_address)
      self.tb.set_pluto_source(str(self.args.pluto_address))
      self.tb.set_tx_zmq_address(str(self.args.uplink_address))
    else:
      print("[!] Warning: bridge module not found. Running in ZMQ-only mode.")

    if self.args.output_file:
      self.file_open()
    if self.args.pcap_output_file:
      self.pcap_open()

  def send_to_sdr(self, data: bytes):
    if len(data) < 15:
      print(f"[!] TX packet too short: {len(data)} bytes")
      return

    header, frequency, bandwidth, spreadfactor, payload_len = struct.unpack_from(">HIHHH", data)
    if header != 0x6383:
      print(f"[!] Unexpected TX packet header: 0x{header:04X}")
      return

    mhz_freq = frequency / 100
    hz_freq = int(mhz_freq * 1_000_000)
    khz_bw = bandwidth / 100
    hz_bw = int(khz_bw * 1000)
    payload = data[12:-3]

    if payload_len != len(payload):
      print(f"[!] Payload length mismatch: header={payload_len}, actual={len(payload)}")

    print(f"\nSending payload to radio: {payload.hex()}")
    print(
      f"FQ: {hz_freq} | BW: {hz_bw} | SF: {spreadfactor} | "
      f"Payload len: {len(payload)}"
    )

    if self.tb:
      self.tb.set_tx_frequency(hz_freq)
      self.tb.set_tx_bandwidth(hz_bw)
      self.tb.set_tx_spread_factor(spreadfactor)

    pdu_bytes = serialize_bytes(payload)
    print("[+] Sending byte payload via ZMQ...")
    try:
      self.txsock.send(pdu_bytes, flags=zmq.NOBLOCK)
    except zmq.error.Again:
      print("[!] TX Queue full. Packet dropped.")

  def connect_to_bridge(self):
    now = time.time()
    if self.bridge_sock is None and (now - self.last_reconnect_time) > 2:
      self.last_reconnect_time = now
      try:
        self.bridge_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bridge_sock.settimeout(0.2)
        self.bridge_sock.connect((self.args.bridge_host, self.args.bridge_port))
        self.bridge_sock.setblocking(False)
        print(f"[*] Connected to C GUI Bridge at {self.args.bridge_host}:{self.args.bridge_port}")
      except (ConnectionRefusedError, socket.error, socket.timeout):
        self.bridge_sock = None

  def send_to_bridge(self, data: bytes):
    if self.bridge_sock:
      payload = bytes([0x64, 0x83]) + struct.pack(">B", len(data)) + data + bytes([0x64, 0x69])
      try:
        self.bridge_sock.sendall(payload)
      except socket.error:
        print("[!] Bridge connection lost")
        self.bridge_sock.close()
        self.bridge_sock = None

  def parse_bridge_data(self, data: bytes):
    if len(data) < 12:
      return
    try:
      header = struct.unpack_from(">H", data)[0]
      if header == 0x6483:
        header, _frequency, _bandwidth, _spreadfactor, tail = struct.unpack_from(">HIHHH", data)
        if header == 0x6483 and tail == 0x6469:
          return
      elif header == 0x6383:
        self.send_to_sdr(data)
    except struct.error as e:
      print(f"[!] Parsing error: {e}")

  def start(self):
    self.running = True
    if self.tb:
      self.tb.start()
      print("[+] GNU Radio script started")

    self.rxctx = zmq.Context()
    self.rxsock = self.rxctx.socket(zmq.SUB)
    self.rxsock.connect(self.args.downlink_address)
    self.rxsock.setsockopt(zmq.SUBSCRIBE, b"")

    self.txctx = zmq.Context()
    self.txsock = self.txctx.socket(zmq.PUSH)
    self.txsock.connect(self.args.uplink_address)
    self.txsock.setsockopt(zmq.LINGER, 0)
    self.txsock.setsockopt(zmq.RCVHWM, 20)
    self.txsock.setsockopt(zmq.SNDHWM, 20)

    print(f"[*] Subscribed to {self.args.downlink_address} (Mode: {self.args.mode.upper()})")

  def stop(self):
    self.running = False
    print("\n[!] Stopping processes...")
    if self.tb:
      self.tb.stop()
      self.tb.wait()
    if self.rxsock:
      self.rxsock.close(0)
    if self.rxctx:
      self.rxctx.term()
    if self.txsock:
      self.txsock.close(0)
    if self.txctx:
      self.txctx.term()
    if self.bridge_sock:
      self.bridge_sock.close()

    self.file_close()
    self.pcap_close()
    print("[*] Clean exit")

  def thread_radio_rx(self):
    while self.running:
      try:
        if self.rxsock.poll(1000, zmq.POLLIN):
          raw_zmq = self.rxsock.recv()
          processed = zmq_frame_to_bytes(raw_zmq)

          if processed:
            print(f"\n=========== {self.args.mode.upper()} PACKET ===========")
            print(f"Length: {len(processed)}")
            print(hexdump(processed))
            self.send_to_bridge(processed)
            self.file_write_frame(processed)
            self.pcap_write_frame(processed)
      except zmq.ZMQError:
        pass

  def thread_bridge_rx(self):
    while self.running:
      self.connect_to_bridge()
      if self.bridge_sock:
        try:
          readable, _, _ = select.select([self.bridge_sock], [], [], 0.5)
          if readable:
            bridge_data = self.bridge_sock.recv(1024)
            if not bridge_data:
              print("[!] Bridge disconnected")
              self.bridge_sock.close()
              self.bridge_sock = None
            else:
              self.parse_bridge_data(bridge_data)
        except (socket.error, select.error):
          self.bridge_sock = None
      else:
        time.sleep(1)

  def run(self):
    def handler(_sig, _frame):
      self.stop()
      sys.exit(0)

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    self.setup()
    self.start()

    t_rx = threading.Thread(target=self.thread_radio_rx, daemon=True)
    t_bridge = threading.Thread(target=self.thread_bridge_rx, daemon=True)

    t_rx.start()
    t_bridge.start()

    try:
      while self.running:
        time.sleep(0.5)
    except KeyboardInterrupt:
      self.stop()


def main():
  parser = argparse.ArgumentParser(
    prog="pylora_bytes_bridge",
    description="GNU Radio LoRa bridge with direct byte payloads",
  )
  parser.add_argument("-f", "--frequency", default=DOWNLINK_FREQ)
  parser.add_argument("-bw", "--bandwidth", default=DOWNLINK_BW)
  parser.add_argument("-sf", "--spread-factor", default=DOWNLINK_SF)
  parser.add_argument("-da", "--downlink-address", default=DEFAULT_DOWNLINK_ADDRESS)
  parser.add_argument("-ua", "--uplink-address", default=DEFAULT_UPLINK_ADDRESS)
  parser.add_argument("-o", "--output-file")
  parser.add_argument("-pcap", "--pcap-output-file")
  parser.add_argument("-p", "--pluto-address", default=DEFAULT_PLUTO_SOURCE)
  parser.add_argument("-m", "--mode", choices=["tm", "tc"], default="tm")
  parser.add_argument("--bridge-host", default=DEFAULT_BRIDGE_HOST)
  parser.add_argument("--bridge-port", type=int, default=DEFAULT_BRIDGE_PORT)

  args = parser.parse_args()
  show_args_config(args)

  ctrl = Controller(args)
  ctrl.run()


if __name__ == "__main__":
  main()
