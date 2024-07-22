# wireshark-v2g - A protocol dissector for V2G communications

[![Build Ubuntu plug-in](https://github.com/ChargePoint/wireshark-v2g/actions/workflows/ubuntu.yml/badge.svg)](https://github.com/ChargePoint/wireshark-v2g/actions/workflows/ubuntu.yml)
[![Build MacOS plug-in](https://github.com/ChargePoint/wireshark-v2g/actions/workflows/macos.yml/badge.svg)](https://github.com/ChargePoint/wireshark-v2g/actions/workflows/macos.yml)
[![Build Windows plug-in](https://github.com/ChargePoint/wireshark-v2g/actions/workflows/windows.yml/badge.svg)](https://github.com/ChargePoint/wireshark-v2g/actions/workflows/windows.yml)

## Overview

Vehicle to Grid protocols are used in charging applications, this
project provides a reference for protocol decode and analysis.

* Wireshark's LUA documentation:  https://wiki.wireshark.org/Lua
* Wireshark's Development documentation: https://wiki.wireshark.org/Development
* OpenV2G documentation: http://openv2g.sourceforge.net

### Linux and MacOS

Copy the `v2g.lua` and `v2gexi.so` files to the Wireshark personal plugin folder:
`~/.local/lib/wireshark/plugins/<version-major>.<version-minor>/epan`.
Note that plugin location is specific to your installed Wireshark version.

For Linux
- copy v2g.lua to `~/.local/lib/wireshark/plugins/4.2/epan`
- copy v2gexi.so to `~/.local/lib/wireshark/plugins/4.2/epan`

For Mac
- copy v2g.lua to `~/.local/lib/wireshark/plugins/4.2/epan`
- copy v2gexi.so to `~/.local/lib/wireshark/plugins/4-2/epan`

### Windows

The personal plugin forlder for Windows is `%APPDATA%/Wireshark/plugins`
and this can have a bit of a different layout to ensure the dll will
load on windows.

- copy the v2g.lua to `%APPDATA%/Wireshark/plugins/4.2/epan`
- copy the v2gexi.dll to `%APPDATA%/Wireshark/plugins/4.2/epan`

__NOTE__: The global plugin folder can also be used in the "Wireshark"
directory under `Program Files` where Wireshark.exe is located. The
plugin folder there can be used as the destination for the v2g files to
be copied.

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
sudo make install
```

Alternatively, to build for Ubuntu 22.04 using a Docker build environment:

```
cd wireshark-v2g
make
cp v2gexi.so ~/.local/lib/wireshark/plugins/4.2/epan/
cp dissector/v2g.lua ~/.local/lib/wireshark/plugins/4.2/epan/
```

#### source plugin

To build and install the plugin as part of Wireshark (ie. permenant)

1) Get the wireshark repo and change directory for future steps
    ```
    git clone https://gitlab.com/wireshark/wireshark
    cd wireshark
    git checkout release-4.2
    ```

2) Copy the V2G plugin to a new `plugins/epan/v2g` directory
    ```
    git clone https://github.com/ChargePoint/wireshark-v2g.git plugins/epan/v2g
    ```

3) Patch the cmake in wireshark to include the v2g plugin
    ```
    git apply plugins/epan/v2g/extern/wireshark-release-4.2.patch
    ```

4) Perform a new wireshark build with the v2g plugin
    ```
    mkdir -p build && cd build
    cmake ..
    make
    sudo make install
    ```

### Mac OS X

The build process is similar to the linux build but based upon
homebrew. This means that most of the setup requires a full build
that encompasses getting the brew recipes.

See the github workflows for macos to see the package installs and
the build steps.

1) Get the wireshark repo and change directory for future steps
    ```
    git clone https://gitlab.com/wireshark/wireshark
    cd wireshark
    git checkout release-4.2
    ```

2) Copy the V2G plugin to a new `plugins/epan/v2g` directory
    ```
    git clone https://github.com/ChargePoint/wireshark-v2g.git plugins/epan/v2g
    ```

3) Patch the cmake in wireshark to include the v2g plugin
    ```
    git apply plugins/epan/v2g/extern/wireshark-release-4.2.patch
    ```

4) Use the wireshark tools script to setup brew to build
    ```
    sh tools/macos-setup-brew.sh
    ```

5) Perform a new wireshark build with the v2g plugin
    ```
    mkdir -p build && cd build

    cmake -DFETCH_lua=ON -GNinja ..

    ninja
    ninja plugins

    # Recommended installation directory
    cp -a run/Wireshark.app /Applications/
    ```

### Windows

The plugins need to be built as part of an intree for this particular
platform. So, the following steps are required to maike a full build
setup.

1) Follow the wireshark windows [step-to-step guide](https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html)

2) Copy the V2G plugin to the `plugins/epan/v2g` directory

3) Patch the wireshark build system to include the plugin
    ```
    git apply plugins/epan/v2g/extern/wireshark-release-4.2.patch
    ```

4) Perform the full build including the plugin

## Usage

Assuming that the build and installation of the plugins has been
performed, the basic testing for integration and display is thru
tshark to quickly check the the plugin parsing and display.

```
tshark -V -r ../wireshark-v2g/pcaps/test.pcap 2>&1
```

*NOTE:* For developers, this is where the fprintf to stderr can be
used to trace and determine possible sources of parsing errors.

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

### Helper Programs

* `yq` (a cousin of `jq`) comes with `xq` which is for XML -> JSON conversion
* `tidy` is also recommended (ships with OSX) to prettify the XML data

After the packet capture has been decoded, you can export the data for
decoding using:

### Build and run the docker container

```
cd tools/docker/decoder
docker build -t decoder:test .
docker run --name=decoder --rm -p 9000:9000/tcp -d decoder:test
```

### Dump all of the EXI-specific payloads in the packet capture stream

The following command will dump all of the packet capture EXI data and
decode it directly to stdout

```
tshark -X lua_script:v2g.lua -r ~/Downloads/Analyzer_M043_decrypted.pcap -Y "exi" -T json | jq '.[]._source.layers.v2gtp.exi.data."data.data"' | sed s/\://g | sed s/\"//g | while read line; do curl -s -X POST -H "Expect:" -H "Format: EXI" -d ${line} http://localhost:9000 |tidy -xml -iq;done
```

### When done, kill the container:

```
docker kill decoder
```
