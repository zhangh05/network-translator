# Cisco VLAN Configuration (Switching Domain)

## VLAN Creation
```
vlan <id>
 name <name>
```

## Access Port
```
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan <id>
```

## Trunk Port
```
interface GigabitEthernet0/1
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan <list>
 switchport trunk native vlan <id>
```

## Voice VLAN
```
interface GigabitEthernet0/1
 switchport access vlan <data_vlan>
 switchport voice vlan <voice_vlan>
```

## Private VLAN
```
vlan <primary_vlan>
 private-vlan primary
 private-vlan association <secondary_vlans>
interface GigabitEthernet0/1
 switchport mode private-vlan host
 switchport private-vlan host-association <primary> <secondary>
```

## VLAN Database Mode
```
vlan database
 vlan <id> name <name>
 vlan <id> mtu <size>
```
