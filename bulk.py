#!?usr/bin/env python3

# davep 16-Mar-2016 ; bulk claim/release DHCP lease 
#
# claim writes IP/chaddr to file for later release.
#

import logging
import struct
import ipaddress
import csv
import uuid

import dhcp
import client

logger = logging.getLogger("dhcp.bulk")

test_target = "192.168.0.1"
my_ip = "192.168.0.5"

client.test_target = ipaddress.ip_address(test_target)
client.my_ip = ipaddress.ip_address(my_ip)

# create an integer for chaddr so can increment it. we'll use pack() to
# convert to 6-byte chaddr
starting_chaddr = 0x004068001100

def encode_chaddr(chaddr):
    buf = struct.pack(">Q", chaddr)
    assert len(buf)==8, buf
    # send back the last 6 bytes
    return buf[-6:]

def claim_many(num_leases, outfilename):
    # stupid human check
    assert 0 < num_leases <= 50, num_leases

    chaddr = starting_chaddr

    with open(outfilename,"w") as outfile:
        # CSV header
        print("chaddr,ip", file=outfile)
        for counter in range(num_leases):
            lease_ip = client.claim(encode_chaddr(chaddr))
            logger.info("claimed ip={} for chaddr={:x}".format(lease_ip, chaddr))
            print("{:x},{}".format(chaddr, lease_ip), file=outfile)

            chaddr += 1

def release_many(lease_list):
    for lease in lease_list:
        logger.info("release chaddr={chaddr:#014x} ip={ip}".format(**lease))
        client.release(encode_chaddr(lease["chaddr"]), lease["ip"])

def _convert_release_fields(row_iter):
    for row in row_iter:
        chaddr = int(row["chaddr"], 16)

        ip = ipaddress.ip_address(row["ip"])
        yield {"chaddr": chaddr, "ip": ip}

def release_using_logfile(logfilename):
    with open(logfilename,'r') as infile:
        reader = csv.DictReader(infile)
        release_many(_convert_release_fields(reader))

