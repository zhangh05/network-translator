# Huawei PBR Configuration (Routing Domain)

## Policy-based Route
```
policy-based-route <name> permit node <seq>
 if-match acl <acl>
 if-match packet-length <min> <max>
 apply ip-address next-hop <ip>
 apply ip-address next-hop <ip> <weight>
 apply output-interface <interface>
 apply ip-address default next-hop <ip>
```

## Apply to Interface
```
interface <interface>
 ip policy-based-route <name>
```

## Local PBR
```
ip local policy-based-route <name>
```
