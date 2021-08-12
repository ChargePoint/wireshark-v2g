# wireshark-v2g - A protocol dissector for V2G communications

## Setup

Wireshark's LUA documentation:  https://wiki.wireshark.org/Lua

## Decrypting TLS payloads

This LUA code will automatically decrypt the V2G traffic if a UDP packet is emitted on port 15118 with the TLS key used to ecrypt the session.
