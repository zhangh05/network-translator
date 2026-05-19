# Huawei Tunnel/GRE Configuration (Routing Domain)

## GRE Tunnel
```
interface Tunnel<id>
 ip address <ip> <mask>
 tunnel-protocol gre
 source <interface-or-ip>
 destination <ip>
 gre key <key>
 mtu <bytes>
 tcp adjust-mss <bytes>
```

## IP-in-IP Tunnel
```
interface Tunnel<id>
 ip address <ip> <mask>
 tunnel-protocol ipip
 source <ip>
 destination <ip>
```
