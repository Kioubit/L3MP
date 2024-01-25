# L3MP
Multiplex up to 16 layer 3 tunnels through a single layer 3 tunnel
- Uses the "diffserv" field in the IPv4/IPv6 header to label packets
- Zero byte overhead (no MTU penalty)
- Performant: Packets are never copied to userspace.
(Uses an eBPF TC direct-action program that runs in the kernel eBPF sandbox)

## Usage:
```
./l3mp <external interface> <path to file with interface-label definitions>
    The interface-label definitions file contains up to 16 entries in this format:
    <interface name>@<label>
    Where <label> is a number from 0 to 16
```