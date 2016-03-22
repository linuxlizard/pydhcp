#!/usr/bin/env python3

import logging

logger = logging.getLogger("dhcp.test")

import dhcp

def test1():
    pkt = dhcp.DiscoverPacket(chaddr=b"\x00\x40\x68\x12\x34\x56")
    pkt.pack()

    pkt2 = dhcp.Packet.unpack(pkt.buf)
    logger.debug(pkt2)
    
    assert pkt.xid==pkt2.xid, (pkt.xid, pkt2.xid)

def run_tests():
    test1()
    
if __name__=='__main__':
    logging.basicConfig(level=logging.DEBUG)
    run_tests()

