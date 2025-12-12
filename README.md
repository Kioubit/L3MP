# L3MP
Multiplex up to 16 layer 3 tunnels through a single layer 3 tunnel
- Uses the `diffserv` field in the IPv4/IPv6 headers to label packets
- Zero byte overhead (no MTU penalty)
- Performant: Packets are never copied to userspace.
(Uses an eBPF TC direct-action program that runs in the kernel eBPF sandbox)


## How It Works

L3MP uses an eBPF TC (Traffic Control) direct-action program to:
1. Intercept packets on the managed interfaces created by the program
2. Mark them using the DiffServ field (6 bits in IP header)
3. Route them through a single external interface
4. Demultiplex incoming packets back to their respective interfaces

## Usage:
```
Usage: L3MP -ext <external interface> -if <interface@label> [-if <interface@label> ...]

Options:
  -ext string
        External interface name (required)
  -if value
        Interface-label pair in format 'interface@label' (can be repeated up to 16 times)

Example:
  L3MP -ext eth0 -if mp1@1 -if mp2@2

Notes:
  - Label must be a number from 0 to 16
  - Maximum 16 interface-label pairs allowed
```

Requires root privileges or the `CAP_NET_ADMIN`, `CAP_BPF`, (`CAP_SYS_RESOURCE`) Linux capabilities.

### Examples

**Simple setup with 2 tunnels:**
```bash
sudo L3MP -ext wg0 -if multi0@1 -if multi1@2
```

**Multiple VPN tunnels:**
```bash
sudo L3MP -ext wg0 \
  -if vpn1@1 \
  -if vpn2@2 \
  -if vpn3@3 \
  -if vpn4@4
```

**Maximum configuration (16 tunnels):**
```bash
sudo L3MP -ext wg0 \
  -if mp1@1 -if mp2@2 -if mp3@3 -if mp4@4 \
  -if mp5@5 -if mp6@6 -if mp7@7 -if mp8@8 \
  -if mp9@9 -if mp10@10 -if mp11@11 -if mp12@12 \
  -if mp13@13 -if mp14@14 -if mp15@15 -if mp16@16
```

### Building
#### Main program
Run ``go build -o L3MP .``
#### Re-compile included eBPF program (Optional)
Requires llvm and clang to be installed. To start the compilation, run ``go generate .``
