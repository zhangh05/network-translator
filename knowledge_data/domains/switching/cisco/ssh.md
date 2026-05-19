# Cisco SSH Configuration (Switching Domain)

## SSH Server
```
hostname <name>
ip domain-name <domain>
crypto key generate rsa modulus <2048|4096>
ip ssh version 2
ip ssh authentication-retries <num>
ip ssh time-out <seconds>
line vty 0 15
 transport input ssh
 login local
```
