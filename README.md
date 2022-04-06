# wireshark-v2g - A protocol dissector for V2G communications

## Overview

Vehicle to Grid protocols are used in charging applications, this
project provides a reference for protocol decode and analysis.

Wireshark's LUA documentation:  https://wiki.wireshark.org/Lua

## Building

This plugin is not distributred as part of the Wireshark source, and
until it is folded in - it can be built as a standalone plugin, or
as part of a full wireshark build.

### Linux

#### standalone plugin

To build and install the plugin on Debian/Ubuntu:

```
sudo add-apt-repository ppa:wireshark-dev/stable -y
sudo apt -get install tshark wireshark wireshark-dev

git clone https://github.com/ChargePoint/wireshark-v2g.git

mkdir wireshark-v2g/build && cd wireshark-v2g/build
cmake ..
make
make install
```

#### source plugin

To build and install the plugin as part of Wireshark (ie. permenant)

1) Get the wireshark repo
    ```
    git clone https://gitlab.com/wireshark/wireshark
    cd wireshark
    git checkout release-3.6
    ```

2) Copy the V2G plugin to a new `plugins/epan/v2g` directory
    ```
    git clone https://github.com/ChargePoint/wireshark-v2g.git plugins/epan/v2g
    ```

3) Patch the cmake in wireshark to include the v2g plugin
    ```
    git apply plugins/epan/v2g/extern/wireshark-release-3.6.patch
    ```

4) Perform a new wireshark build with the v2g plugin
    ```
    mkdir -p build && cd build
    cmake ..
    make
    make install
    ```

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
$ ./extract_secrets.py -f ../../pcaps/plc_20210810T190140.pcap
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


## Decoding an entire EXI stream

### Helper programs

`yq` (a cousin of `jq`) comes with the command `xq` which is for XML -> JSON conversion.
`tidy` is also recommended (ships with OSX) to prettify the XML data returned

After the packet capture has been decoded, you can export the data for decoding using:

### Build and run the docker container

```
docker build -t decoder:test .
docker run --name=decoder --rm -p 9000:9000/tcp -d decoder:test
```

### Dump all of the EXI-specific payloads in the packet capture stream

The following command will dump all of the packet capture EXI data and decode it directly to stdout

```
tshark -X lua_script:v2g.lua -r ~/Downloads/Analyzer_M043_decrypted.pcap -Y "exi" -T json | jq '.[]._source.layers.v2gtp.exi.data."data.data"' | sed s/\://g | sed s/\"//g | while read line; do curl -s -X POST -H "Expect:" -H "Format: EXI" -d ${line} http://localhost:9000 |tidy -xml -iq;done
```

### When done, kill the container:

```
docker kill decoder
```

