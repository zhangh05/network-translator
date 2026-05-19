# Huawei VLAN Configuration (Switching Domain)

## VLAN Creation
```
vlan <id>
 description <text>
```

## Access Port
```
interface GigabitEthernet0/0/1
 port link-type access
 port default vlan <id>
```

## Trunk Port
```
interface GigabitEthernet0/0/1
 port link-type trunk
 port trunk allow-pass vlan <list>
 port trunk pvid vlan <id>
```

## Hybrid Port
```
interface GigabitEthernet0/0/1
 port link-type hybrid
 port hybrid untagged vlan <list>
 port hybrid tagged vlan <list>
 port hybrid pvid vlan <id>
```

## Voice VLAN
```
interface GigabitEthernet0/0/1
 voice-vlan <id> enable
```

## VLAN Batch
```
vlan batch <id1> [to <id2>]
vlan batch <id1> <id2> <id3>
```
