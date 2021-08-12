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

### Automatic method

Under the tools folder is a simple python script that will take a V2G
debug packet capture, extract the secret, use wireshark's `editcap`
utility to extract the TLS session key and apply it across the capture.

#### Prereq installation
If you have python3 installed, you can install `scapy` or use `pipenv` which
is included in the `tools/` directory.

To install scapy without pipenv: `python3 -m pip install scapy==2.4.5`

With pipenv: `pipenv shell`

#### Running `extract_secrets.py`

```shell
$ ./extract_secrets.py -f ../pcaps/plc_20210810T190140.pcap
WARNING: No IPv4 address found on en3 !
WARNING: No IPv4 address found on en4 !
WARNING: more No IPv4 address found on en1 !
TLS was requested by fe80::218:23ff:fe0f:fbfe:49156
found potential session key on raw UDP packet with dest port 49156
writing ../pcaps/plc_20210810T190140_secret.txt
editcap --inject-secrets tls,../pcaps/plc_20210810T190140_secret.txt ../pcaps/plc_20210810T190140.pcap ../pcaps/plc_20210810T190140_decrypted.pcap
```

### Manual method

Most debugging captures will record the TLS session key with a single UDP
packet sent to the Vehicle port from a random port. Inside you'll find a key
like the following:

```
CLIENT_RANDOM 6112d032475e758bbf8eaf2b0a540f3f2c7a6f6d1a9b48935d16c468086822f5 8471a233b4f1926084b68977a28ef8b65f59fea4b4942800539ba1d991a98c3f81e29a109d394606bd91286981dbd122
```
