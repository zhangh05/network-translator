# Cisco Tunnel/GRE Configuration (Routing Domain)

## GRE Tunnel
```
interface Tunnel<id>
 ip address <ip> <mask>
 tunnel source <interface-or-ip>
 tunnel destination <ip>
 tunnel mode gre ip
 ip mtu <bytes>
 ip tcp adjust-mss <bytes>
 keepalive <seconds> <retries>
```

## IP-in-IP Tunnel
```
interface Tunnel<id>
 ip address <ip> <mask>
 tunnel source <ip>
 tunnel destination <ip>
 tunnel mode ipip
```

## Tunnel with IPsec
```
crypto isakmp policy <id>
 encryption aes 256
 authentication pre-share
 group 14
crypto isakmp key <key> address <peer-ip>
crypto ipsec transform-set <name> esp-aes 256 esp-sha-hmac
 mode tunnel
crypto ipsec profile <name>
 set transform-set <name>
interface Tunnel<id>
 tunnel protection ipsec profile <name>
```
