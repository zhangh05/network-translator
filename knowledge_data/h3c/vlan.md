# H3C VLAN Configuration

## VLAN Creation
```
vlan <id>
 description <text>
```

## Access Port
```
interface GigabitEthernet0/0/1
 port link-type access
 port access vlan <id>
```

## Trunk Port
```
interface GigabitEthernet0/0/1
 port link-type trunk
 port trunk permit vlan <list>
 port trunk pvid vlan <id>
```

## Hybrid Port
```
interface GigabitEthernet0/0/1
 port link-type hybrid
 port hybrid vlan <list> untagged
 port hybrid vlan <list> tagged
 port hybrid pvid vlan <id>
```

## Voice VLAN
```
interface GigabitEthernet0/0/1
 voice-vlan <id> enable
```

## VLAN Batch (v7)
```
vlan <id1> to <id2>
vlan <id1> <id2> <id3>
```
