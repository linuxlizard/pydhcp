#!/usr/bin/env python3

import logging
import ipaddress

logger = logging.getLogger("dhcp.test")

import dhcp

def test1():
    pkt = dhcp.DiscoverPacket(chaddr=b"\x00\x40\x68\x12\x34\x56")
    pkt.pack()

    pkt2 = dhcp.Packet.unpack(pkt.buf)
    logger.debug(pkt2)
    
    assert pkt.xid==pkt2.xid, (pkt.xid, pkt2.xid)
    assert dhcp.dhcpmessage in pkt.options
    msgtype = pkt.options[dhcp.dhcpmessage].value
    assert msgtype==dhcp.DISCOVER, msgtype
    

def test2():
    # fiddle with lists of IP addresses, packing and unpacking
    time_server = dhcp.IP_Option(dhcp.time_server, "time server")
    buf = time_server.pack()
    assert len(buf)==2, len(buf)

    # test packing
    opts = time_server.new((ipaddress.ip_address("10.0.0.1"),ipaddress.ip_address("10.0.0.2")))
    buf = opts.pack()
    print(buf)
    assert len(buf)==2+4+4, len(buf)

    opts = time_server.new()
    opts.unpack(buf)
    print(opts)

def run_tests():
    test1()
    
    test2()

if __name__=='__main__':
    logging.basicConfig(level=logging.DEBUG)
    run_tests()

