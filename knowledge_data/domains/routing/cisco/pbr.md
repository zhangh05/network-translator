# Cisco PBR Configuration (Routing Domain)

## Route-map PBR
```
route-map <name> permit <seq>
 match ip address <acl>
 match length <min> <max>
 set ip next-hop <ip>
 set ip next-hop verify-availability
 set ip next-hop <ip> <weight>
 set interface <interface>
 set ip default next-hop <ip>
```

## Apply to Interface
```
interface <interface>
 ip policy route-map <name>
```

## Local PBR
```
ip local policy route-map <name>
```
