#!/usr/bin/env python3

# davep 07-Mar-2016 ;  DHCP Discovery

import sys
import socket
import struct

import dhcp

test_target = "127.0.0.1"
#test_target = "172.19.9.238"
#test_target = "192.168.0.1"

my_chaddr = b"\x00\x40\x68\x00\x11\x22"
my_chaddr = b"\x80\xee\x73\x95\xcf\x61"

def make_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    return sock

def run(sock):
    pkt = dhcp.DiscoverPacket(chaddr=my_chaddr)
    request_options = (dhcp.OPT_SUBNET_MASK, dhcp.OPT_ROUTER, dhcp.OPT_DNS_NAME_SERVER, dhcp.OPT_DOMAIN_NAME,
                        dhcp.OPT_NETWORK_TIME_SERVER, dhcp.OPT_BROADCAST_ADDRESS, dhcp.OPT_TIME_OFFSET)
    pkt.add_option(dhcp.DHCPParameterRequestList(request_options))
#    pkt.add_option(dhcp.VendorClassID("∞ Python DHCP Test Client ∞"))

    pkt.giaddr, = struct.unpack(">L",socket.inet_aton("172.19.9.34"))
    pkt.flags = dhcp.FLAGS_BROADCAST

#    sock.bind(("192.168.0.5", dhcp.CLIENT_PORT))
    sock.sendto(pkt.pack(), (test_target, dhcp.SERVER_PORT))

def main():
    sock = make_socket()
    run(sock)
    sock.close()

if __name__=='__main__':
    main()
