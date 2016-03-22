#!/usr/bin/env python3

# davep 07-Mar-2016 ;  DHCP Discovery

import sys
import socket
import struct
import logging

logger = logging.getLogger("dhcp.discover")

import dhcp

#test_target = "127.0.0.1"
#test_target = "172.19.9.238"
test_target = "192.168.0.1"

my_ip = "192.168.0.5"

my_chaddr = b"\x00\x40\x68\x00\x11\x22"
#my_chaddr = b"\x80\xee\x73\x95\xcf\x61"

def make_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

    return sock

def run():
    pkt = dhcp.DiscoverPacket(chaddr=my_chaddr)
    request_options = (dhcp.subnet_mask, dhcp.router, dhcp.domain_name_server, dhcp.domain_name,
                        dhcp.network_time_server, dhcp.broadcast_address, dhcp.time_offset)
    pkt.set_option(dhcp.param_request_list, request_options)
    pkt.pack()
#    pkt.add_option(dhcp.VendorClassID("∞ Python DHCP Test Client ∞"))

    # act as a gateway so as to be the least disruptive on the local network
    # (unicast *EVERYTHING*, no broadcast transmission ever!)
    pkt.giaddr, = struct.unpack(">L",socket.inet_aton(my_ip))

    # requires server to broadcast responses (I will never broadcast)
#    pkt.flags = dhcp.FLAGS_BROADCAST

    # I'm acting as a DHCP gateway so need to Tx/Rx different ports because
    # dnsmasq won't respond if udp.src_port==SERVER_PORT but sends its response
    # to udp.dst_port==SERVER_PORT 
    tx_sock = make_socket()
    rx_sock = make_socket()

#    sock.bind(("192.168.0.5", 0))
    tx_sock.bind((my_ip, dhcp.CLIENT_PORT))
    rx_sock.bind((my_ip, dhcp.SERVER_PORT))

    tx_sock.sendto(pkt.pack(), (test_target, dhcp.SERVER_PORT))

    buf, server = rx_sock.recvfrom(65535)
    logger.debug("recv bytes=%d from %s", len(buf), server)

    reply_pkt = dhcp.Packet.unpack(buf)
    logger.info("reply_pkt=%s", reply_pkt)
    logger.info("opts=%s", reply_pkt.options)

    tx_sock.close()
    rx_sock.close()

if __name__=='__main__':
    logging.basicConfig(level=logging.DEBUG)
    run()
