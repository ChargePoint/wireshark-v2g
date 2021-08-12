# wireshark-v2g - A protocol dissector for V2G communications

## Setup

Wireshark's LUA documentation:  https://wiki.wireshark.org/Lua

### Mac OS X

Install wireshark application in the usual location, and this will
allow access to the tshark application to run the script and debug
the output.

```
/Applications/Wireshark.app/Contents/MacOS/tshark \
    -X lua_script:v2g.lua -r test.pcap
```

### Win 10

Install wireshark application in the usual location, and this will
allow access to the tshark application to run the script and debug
the output.

```
c:\Program Files (x86)\Wireshark\tshark.exe-X lua_script:v2g.lua -r test.pcap
```

## Decrypting TLS payloads

This LUA code will automatically decrypt the V2G traffic if a UDP packet is
emitted on port 15118 with the TLS key used to ecrypt the session.
