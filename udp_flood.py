#!/usr/bin/env python

from bcc import BPF
import sys

bpf = BPF(src_file="udp_flood.c")

interface = "enp4s0"
try:

    fn = bpf.load_func("xdp_udp_flood", BPF.XDP)
    bpf.attach_xdp(interface, fn, 0)
except Exception as e:
    print(f"Failed to load XDP program: {e}")
    sys.exit(1)

print("XDP program loaded on interface {}. Monitoring for UDP floods...".format(interface))

try:
    while True:
        bpf.trace_print()
except KeyboardInterrupt:
    pass
finally:
    bpf.remove_xdp(interface, 0)  