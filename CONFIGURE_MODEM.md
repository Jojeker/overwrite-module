# Configuring the modem to connect to a network

- We provide the instructions to connect to a network below
- Tested on Sunrise LTE
- A full trace is in `AT_COMMANDS_CONFIGURE.txt`

!!! WARNING !!!
Disable modem manager first, otherwise it will interfere!
sudo systemctl stop ModemManager.service


### Configurations necessary

```

# Ethenernet must be disabled
AT+QCFG="ethernet"
+QCFG: "ethernet",0

# 5GLan should be disabled for all PDU sessions
AT+QCFG="5glan"
+QCFG: "5glan",1,0
+QCFG: "5glan",2,0
+QCFG: "5glan",3,0
+QCFG: "5glan",4,0
+QCFG: "5glan",5,0
+QCFG: "5glan",6,0
+QCFG: "5glan",7,0
+QCFG: "5glan",8,0

# Driver selected by default
AT+QCFG="usbnet"
+QCFG: "usbnet",5

# Must be set (default though)
AT+QCFG="nat"
+QCFG: "nat",5

# The apn might be autoconfigured by the operator
AT+CGDCONT=1,"IP","internet"

# Reboot to make sure we have all the necessary setup
AT+CFUN=1,1

```

### Optional Configurations 

```
# For debugging..
AT+QCFG="ims"
+QCFG: "ims",0
```

### Connecting from a Booted Modem

```
AT+QENG="servingcell"
+QENG: "servingcell","CONECT","LTE","FDD",228,02,1CA6B8E,64,522,1,4,4,B3B3,-105,-7,-80,3,7,17,20
# The modem is registered but in RRC_IDLE

# This command is the RIL telling the baseband to stop/start the PDU session
AT+QNETDEVCTL=1,1,0
>> Expected output
+QNETDEVSTATUS: 1,1,"IPV4",0

# After that the connection is established
```


