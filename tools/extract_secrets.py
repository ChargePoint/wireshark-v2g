#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.inet6 import UDP as UDP6
from scapy.layers.inet6 import IPv6
from scapy.layers.inet6 import TCP as TCP6
from pathlib import Path
import argparse
import subprocess


sdp_request_type = {
    "sdp_req": 0x9000,
    "sdp_resp": 0x9001,
    "exi": 0x8001,
}

SECURITY_FIELD = XByteEnumField("security", 0, {0x00: "True", 0x10: "False"})
TRANSPORT_FIELD = XByteEnumField("transport", 0, {0x00: "TCP", 0x10: "UDP"})


class SDP(Packet):
    name = "SECC Discovery Protocol"
    fields_desc = [
        XByteField("version", 1),
        XByteField("inverted_version", 1),
        XShortEnumField("payload_type", sdp_request_type["sdp_req"],
                        {v: k for k, v in sdp_request_type.items()}),
        IntField("payload_size", 0),
    ]


class SDPRequest(Packet):
    name = "SECC Discovery Protocol Request"
    fields_desc = [
        SECURITY_FIELD,
        TRANSPORT_FIELD,
    ]


class SDPResponse(Packet):
    name = "SECC Discovery Protocol Response"
    fields_desc = [
        IP6Field("secc_ip_addr", "::1"),
        ShortField("secc_port", 0),
        SECURITY_FIELD,
        TRANSPORT_FIELD,
    ]


class EXI(Packet):
    name = "EXI Encoded Data Packet"
    fields_desc = [
        StrField("exi_cookie", "")
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--file", help="path to pcap file", required=True)
    ap.add_argument("-v", "--verbose", help="print packets", action="count", default=0)

    bind_layers(IPv6, UDP6)
    bind_layers(UDP6, SDP, dport=15118)
    bind_layers(UDP6, SDP, sport=15118)
    bind_layers(SDP, SDPRequest, payload_type=sdp_request_type["sdp_req"])
    bind_layers(SDP, SDPResponse, payload_type=sdp_request_type["sdp_resp"])
    bind_layers(SDP, EXI, payload_type=sdp_request_type["exi"])

    args = ap.parse_args()
    cap = rdpcap(args.file)
    secure_packet_port = None
    tls_secure_packet_port = None
    has_security = False
    tls_key = None
    secc_port = None

    for pkt in cap:
        if args.verbose > 0 and pkt.haslayer(SDP):
            pkt.show()

        if pkt.haslayer(SDPRequest):
            if not bool(pkt.security):
                secure_packet_port = pkt[UDP6].sport
                print(f"TLS was requested by {pkt[IPv6].src}:{secure_packet_port}")
                has_security = True
            else:
                print("Session did not request security, no secret to extract")

        # also need try the secc port
        if pkt.haslayer(SDPResponse):
            secc_port = pkt[SDPResponse].secc_port

        # Looking for SYN with secc_port which is typically the start of the TLS session.
        # Some debug flows will insert this key into the TCP port streams as a UDP packet which will
        # usually be followed up with an ICMPv6 Port Unreachable
        if pkt.haslayer(TCP6) and pkt[TCP6].flags == "S":
            if pkt[TCP6].dport == secc_port:
                tls_secure_packet_port = pkt[TCP6].sport

        if has_security and not pkt.haslayer(SDP):
            if pkt.haslayer(UDP6):
                if pkt[UDP6].dport == secure_packet_port:
                    print(f"found potential session key on raw UDP packet with dest port {secure_packet_port}")
                    tls_key = pkt[UDP6].load.decode("utf8", "ignore")
                if pkt[UDP6].dport == tls_secure_packet_port:
                    print(f"found potential session key on raw UDP packet with dest port {tls_secure_packet_port}")
                    tls_key = pkt[UDP6].load.decode("utf8", "ignore")

    if tls_key is not None:
        old_file = Path(args.file)
        new_file = Path(f'{old_file.parent}/{old_file.name.replace(old_file.suffix, "_secret.txt")}')
        decrypted_out = Path(f'{old_file.parent}/{old_file.name.replace(old_file.suffix, "_decrypted.pcap")}')
        print(f"writing {new_file}")
        with Path(new_file).open(mode="w") as f:
            f.write(tls_key)

        cmd = f"editcap --inject-secrets tls,{new_file} {old_file} {decrypted_out}"

        try:
            print(cmd)
            subprocess.run(cmd.split(), check=True)
            return
        except subprocess.CalledProcessError:
            print("cannot find 'editcap' command")

    print("unable to find TLS session key")


if __name__ == '__main__':
    main()
