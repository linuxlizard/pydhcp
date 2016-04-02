#!/usr/bin/env python3

# davep 15-Mar-2016 ; DHCP Client
#
# Never never never broadcast any packets. Only unicasts to a specific known
# server IP address. Best effort taken to not disrupt normal network operations.
#

import sys
import socket
import struct
import logging
import ipaddress

import dhcp

logger = logging.getLogger("dhcp.client")

#test_target = "127.0.0.1"
#test_target = "172.19.9.238"
test_target = "192.168.0.1"
#test_target = "192.168.10.1"
test_target = ipaddress.ip_address(test_target)

#my_ip = "127.0.0.100"
my_ip = "192.168.0.5"
#my_ip = "192.168.10.5"
my_ip = ipaddress.ip_address(my_ip)

#my_chaddr = b"\x00\x40\x68\x00\x11\x1d"
#my_chaddr = b"\x80\xee\x73\x95\xcf\x61"

client_id = None
#client_id = "a<img src=a onerror=alert(1)>"
#client_id = "Python DHCP Test Client"

def claim(client_chaddr):
    # I'm acting as a DHCP gateway so need to Tx/Rx different ports because
    # dnsmasq won't respond if udp.src_port==SERVER_PORT but sends its response
    # to udp.dst_port==SERVER_PORT 
    tx_sock = dhcp.make_socket()
    rx_sock = dhcp.make_socket()

    tx_sock.bind((str(my_ip), dhcp.CLIENT_PORT))
    rx_sock.bind((str(my_ip), dhcp.SERVER_PORT))

    # DISCOVER
    disco_pkt = dhcp.DiscoverPacket(chaddr=client_chaddr)
    request_options = (dhcp.subnet_mask, dhcp.router, dhcp.domain_name_server, dhcp.domain_name,
                        dhcp.network_time_server, dhcp.broadcast_address, dhcp.time_offset)
    disco_pkt.set_option(dhcp.param_request_list, request_options)
    if client_id:
        disco_pkt.set_option(dhcp.clientid, client_id.encode("UTF-8"))

    # act as a gateway so as to be the least disruptive on the local network
    # (unicast *EVERYTHING*, no broadcast transmission ever!)
    disco_pkt.giaddr = my_ip

    # requires server to broadcast responses (I will never broadcast)
#    pkt.flags = dhcp.FLAGS_BROADCAST

    tx_sock.sendto(disco_pkt.pack(), (str(test_target), dhcp.SERVER_PORT))

    # OFFER
    buf, server = rx_sock.recvfrom(65535)
    logger.debug("recv bytes=%d from %s", len(buf), server)

    offer_pkt = dhcp.Packet.unpack(buf)
    logger.info("offer_pkt=%s", offer_pkt)
    logger.info("opts=%s", offer_pkt.options)

    # I should be unicasting to the ONLY server on a captive subnet
    if offer_pkt.xid != disco_pkt.xid:
        errmsg = "offer xid={:x} != discover xid={:x}".format(offer_pkt.xid, disco_pkt.xid)
        raise dhcp.DHCPTransactionError(errmsg)

    # REQUEST
    request_pkt = dhcp.RequestPacket(chaddr=client_chaddr, xid=offer_pkt.xid)
    request_pkt.giaddr = my_ip
    request_pkt.ciaddr = offer_pkt.yiaddr
    request_pkt.siaddr = offer_pkt.siaddr
    if client_id:
        request_pkt.set_option(dhcp.clientid, client_id.encode("UTF-8"))

    tx_sock.sendto(request_pkt.pack(), (str(test_target), dhcp.SERVER_PORT))

    # ACK (or NAK)
    buf, server = rx_sock.recvfrom(65535)
    logger.debug("recv bytes=%d from %s", len(buf), server)

    ack_pkt = dhcp.Packet.unpack(buf)
    logger.info("ack_pkt=%s", ack_pkt)
    logger.info("opts=%s", ack_pkt.options)

    if offer_pkt.xid != request_pkt.xid:
        errmsg = "offer xid={:x} != request xid={:x}".format(offer_pkt.xid, request_pkt.xid)
        raise dhcp.DHCPTransactionError(errmsg)

    tx_sock.close()
    rx_sock.close()

    return offer_pkt.yiaddr

def release(client_chaddr, client_ipaddr):
    tx_sock = dhcp.make_socket()
    tx_sock.bind((str(my_ip), dhcp.CLIENT_PORT))

    release_pkt = dhcp.ReleasePacket(chaddr=client_chaddr)
    # serverid option makes dnsmasq happy
    release_pkt.set_option(dhcp.serverid, [test_target])

    release_pkt.giaddr = my_ip
    release_pkt.ciaddr = client_ipaddr
    release_pkt.siaddr = test_target

    tx_sock.sendto(release_pkt.pack(), (str(test_target), dhcp.SERVER_PORT))

    # there is no response from server 

    tx_sock.close()

if __name__=='__main__':
    import time

    logging.basicConfig(level=logging.DEBUG)

    chaddr = b"\x00\x40\x68\x00\x11\x1e"
    client_ip = claim(chaddr)
    time.sleep(1)
    release(chaddr, client_ip)

