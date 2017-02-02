#!/usr/bin/env python3

# davep 08-Jan-2017 ;	broadcast a discovery, report offers
#						Created to help find rogue DHCP servers on a subnet.
#						Also an excuse to learn asyncio.

import sys
import logging
import socket
import pwd
import time
import os
import asyncio
import signal
import functools
import subprocess

logger = logging.getLogger("dhcp.bcast")

import dhcp

# get the dev's mac address using "ip link $dev"
IPCMD_PATH = "/sbin/ip"

# from the python asyncio docs
def ask_exit(signame, loop, disco_task):
	# TODO how do I cancel dhcp_discover() so I don't get the RuntimeError on ^C ?
	logger.info("got signal %s: exit", signame)
	disco_task.cancel()
#	loop.stop()

def dhcp_recv(sock, loop):
	logger.info("dhcp_recv")

	buf, server = sock.recvfrom(65535)
	# TODO should I be using the loop.sock_recv() ?
#	buf = loop.sock_recv(sock, 65535)
	logger.info("from server=%s len=%d", server, len(buf))
	offer_pkt = dhcp.Packet.unpack(buf)
	logger.info("from offer_pkt=%s", offer_pkt)
	logger.info("opts=%s", offer_pkt.options)

async def dhcp_discover(sock, disco_pkt):
	buf = disco_pkt.pack()
	while True:
		ret = sock.sendto(buf, ("255.255.255.255", dhcp.SERVER_PORT))
		logger.info("sendto ret=%d", ret)
		await asyncio.sleep(10)

def make_socket(dev):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode())
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)

	# "Starting with Linux 2.2, all IP header fields and options can be set
	#  using IP socket options." raw(7)
	# how do I set the source IP address to 0.0.0.0 ?
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_DONTROUTE, True)

#	IP_FREEBIND=15
#	ret = sock.setsockopt(socket.IPPROTO_IP, IP_FREEBIND, True)
#	print(ret)
#	sock.setsockopt(socket.IPPROTO_IP, socket.IP_FREEBIND, True)

	# asyncio wants nonblocking
	sock.setblocking(0)

	return sock

def get_macaddr(dev):
	output = subprocess.check_output((IPCMD_PATH, "link", "show", dev), shell=False)
	# let's hope ip(8) has stable output
	fields = (output.split("\n".encode())[1]).split()
	return fields[1]

def main():
	dev = sys.argv[1]
	my_chaddr = get_macaddr(dev)

	tx_sock = make_socket(dev)
	tx_sock.bind(('', dhcp.CLIENT_PORT))

	# drop privs because why not
	nobody = pwd.getpwnam("nobody")
	os.setgid(nobody.pw_gid)
	os.setuid(nobody.pw_uid)

	disco_pkt = dhcp.DiscoverPacket(chaddr=my_chaddr)
	request_options = (dhcp.subnet_mask, dhcp.router, dhcp.domain_name_server, dhcp.domain_name,
						dhcp.network_time_server, dhcp.broadcast_address, dhcp.time_offset)
	disco_pkt.set_option(dhcp.param_request_list, request_options)
	# request/require server to broadcast the response
	disco_pkt.flags = dhcp.FLAGS_BROADCAST

	loop = asyncio.get_event_loop()
	loop.set_debug(True)

	loop.add_reader(tx_sock.fileno(), 
					functools.partial(dhcp_recv, tx_sock, loop))

	disco_task = loop.create_task(dhcp_discover(tx_sock, disco_pkt))

	# from the python docs
	for signame in ('SIGINT', 'SIGTERM'):
		loop.add_signal_handler(getattr(signal, signame),
								functools.partial(ask_exit, signame, loop, disco_task))

	# and away we go
	try:
		loop.run_until_complete(disco_task)
	except asyncio.CancelledError:
		logger.info("cancelled")
	finally:
		logger.info("hello from finally")
		loop.close()

	tx_sock.close()

if __name__=='__main__':
	logging.basicConfig(level=logging.DEBUG)
	main()
