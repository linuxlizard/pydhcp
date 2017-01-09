#!/usr/bin/env python3

# davep 08-Jan-2017 ;	broadcast a discovery, report offers
#						Created to help find rogue DHCP servers on a subnet.
#						Also an excuse to learn asyncio.

import logging
import socket
import pwd
import time
import os
import asyncio
import signal
import functools

logger = logging.getLogger("dhcp.bcast")

import dhcp

# TODO get from command line
dev="wlan1"

# TODO get the dev's mac address 
my_chaddr = b"\x00\xc0\xca\x84\xad\x18"

# from the python asyncio docs
def ask_exit(signame, loop):
	logger.info("got signal %s: exit", signame)
	loop.stop()

def dhcp_recv(sock, loop):
	logger.info("dhcp_recv")

	buf, server = sock.recvfrom(65535)
#	buf = loop.sock_recv(sock, 65535)
	logger.info("from server=%s len=%d", server, len(buf))
	offer_pkt = dhcp.Packet.unpack(buf)
	logger.info("from offer_pkt=%s", offer_pkt)
	logger.info("opts=%s", offer_pkt.options)

def make_socket():
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode())
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)

	# asyncio wants nonblocking
	sock.setblocking(0)

	return sock

def main():
	tx_sock = make_socket()
	tx_sock.bind(('', dhcp.CLIENT_PORT))

#	rx_sock = make_socket()
#	rx_sock.bind(('', dhcp.SERVER_PORT))

	# drop privs because why not
	nobody = pwd.getpwnam("nobody")
	os.setgid(nobody.pw_gid)
	os.setuid(nobody.pw_uid)

	disco_pkt = dhcp.DiscoverPacket(chaddr=my_chaddr)
	request_options = (dhcp.subnet_mask, dhcp.router, dhcp.domain_name_server, dhcp.domain_name,
						dhcp.network_time_server, dhcp.broadcast_address, dhcp.time_offset)
	disco_pkt.set_option(dhcp.param_request_list, request_options)
	disco_pkt.flags = dhcp.FLAGS_BROADCAST

	loop = asyncio.get_event_loop()
	loop.set_debug(True)

	# from the python docs
	for signame in ('SIGINT', 'SIGTERM'):
		loop.add_signal_handler(getattr(signal, signame),
								functools.partial(ask_exit, signame, loop))

	loop.add_reader(tx_sock.fileno(), 
					functools.partial(dhcp_recv, tx_sock, loop))

	# TODO hook this into the loop somehow
	ret = tx_sock.sendto(disco_pkt.pack(), ("255.255.255.255", dhcp.SERVER_PORT))
	logger.info("sendto count=%d", ret)

	# and away we go
	try:
		loop.run_forever()
	finally:
		loop.close()

#	counter = 0
#	while counter < 10:
#		ret = tx_sock.sendto(disco_pkt.pack(), ("255.255.255.255", dhcp.SERVER_PORT))
#		logger.info("sendto count=%d", ret)
#
#		buf, server = tx_sock.recvfrom(65535)
#		logger.info("from server=%s len=%d", server, len(buf))
#		offer_pkt = dhcp.Packet.unpack(buf)
#		logger.info("from server=%s offer_pkt=%s", server ,offer_pkt)
#		logger.info("opts=%s", offer_pkt.options)
#
#		time.sleep(1)
#		counter += 1

	tx_sock.close()
#	rx_sock.close()

if __name__=='__main__':
	logging.basicConfig(level=logging.DEBUG)
	main()
