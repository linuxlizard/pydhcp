#!/usr/bin/env python3 

# davep 07-Mar-2016 ;  DHCP in Python for testing
#
# https://tools.ietf.org/html/rfc2131
# https://tools.ietf.org/html/rfc1533

import struct
import random
import socket

SERVER_PORT = 67
CLIENT_PORT = 68

BOOTP_REQUEST=1
BOOTP_REPLY=2

FLAGS_BROADCAST = (1<<15)

chaddr_len = 16
sname_len = 64
bootfile_len = 128


OPT_PAD = 0
OPT_END = 255
OPT_SUBNET_MASK = 1
OPT_TIME_OFFSET = 2
OPT_ROUTER = 3
OPT_DNS_NAME_SERVER = 6
OPT_HOST_NAME = 12
OPT_DOMAIN_NAME = 15
OPT_BROADCAST_ADDRESS = 28
OPT_NETWORK_TIME_SERVER = 42

OPT_DHCP_REQUEST_IP = 50
OPT_DHCP_IP_LEASE_TIME = 51

# fields in OPT_DHCP_MESSAGE options field
DISCOVER = 1
OFFER = 2
REQUEST = 3
DECLINE = 4
ACK = 5
NAK = 6
RELEASE = 7

class Option:
    # descendents override
    opcode = 0
    length = 0

    def __init__(self):
        self.buf = bytes()

    def pack(self):
        # just enough brains to pack self.opcode
        # (can encode/decode PAD and END options)
        self.buf = struct.pack("B", self.opcode)
        return self.buf

    def unpack(self):
        # TODO
        pass

class OptionPad(Option):
    opcode = 0
    length = 1

class OptionEnd(Option):
    opcode = OPT_END
    length = 1

class IPv4Option(Option):
    # base class of an option that contains an IPv4 address
    length = 4

    def __init__(self, ipv4_addr):
        self.addr = ipv4_addr
        self.buf = b''

    def pack(self):
        self.buf = socket.inet_aton(self.addr)
        return self.buf

class SubnetMaskOption(IPv4Option):
    opcode = OPT_SUBNET_MASK

class DHCPMessageOption(Option):
    opcode = 53
    length = 1

    def __init__(self, message):
        super().__init__()
        self.message = message

    def pack(self):
        self.buf = struct.pack("BBB", self.opcode, self.length, self.message)
        return self.buf

class DHCPParameterRequestList(Option):
    opcode = 55
    # length is calculated at run-time

    def __init__(self, options_list):
        super().__init__()
        self.options_list = options_list

    def pack(self):
        self.buf = struct.pack("BB%dB"%len(self.options_list), 
                            self.opcode, len(self.options_list), *self.options_list)
        return self.buf

class VendorClassID(Option):
    opcode = 60
    # length is calculated at run-time

    def __init__(self, vendor_id_str):
        super().__init__()
        self.vid = vendor_id_str

    def pack(self):
        vid = self.vid.encode("UTF-8")
        self.buf = struct.pack("BB", self.opcode, len(vid)) + vid
        return self.buf

class OptionsList:
    def __init__(self):
        self.options = []
        self.buf = b'\x63\x82\x53\x63'

    def add(self, option):
        self.options.append(option)

    def pack(self):
        # TODO add padding (align on some sort of byte/word boundaries?)
        self.buf = b'\x63\x82\x53\x63'
        self.buf += b''.join([opt.pack() for opt in self.options])
        self.buf += OptionEnd().pack()
        return self.buf
        
class Packet:
    op = None 
    htype = 1
    hlen = 6 # ethernet

    fmt = ">BBBBLHHLLLL16s64s128s312s"

    def __init__(self, **kwargs):
        self.buf = None
        self.hops = 0
        self.xid = random.randint(0,2**32-1)
        self.secs = 0
        self.flags = 0
        self.ciaddr = 0
        self.yiaddr = 0
        self.siaddr = 0
        self.giaddr = 0
        self.chaddr = kwargs.get("chaddr", b'')
        self.sname = ""
        self.bootfile = ""

        # array of Option instances
        self.options = OptionsList()

    def pack(self):
        self.buf = struct.pack(self.fmt,
                        # Bytes (four fields)
                        self.op, self.htype, self.hlen, self.hops,

                        # Long (uint32)
                        self.xid,

                        # sHort (uint16) (two fields)
                        self.secs, self.flags,

                        # Long (uint32) (four IP addresses)
                        self.ciaddr, self.yiaddr, self.siaddr, self.giaddr,

                        # 16 byte chaddr
                        self.chaddr,

                        # 64-byte server hostname
                        self.sname.encode("UTF-8"),

                        # 128-byte boot file name
                        self.bootfile.encode("UTF-8"),

                        self.options.pack()
                   )
        return self.buf
        
    def add_option(self, option):
        self.options.add(option)

    def unpack(self):
        # TODO
        pass

class RequestPacket(Packet):
    op = BOOTP_REQUEST

class ReplyPacket(Packet):
    op = BOOTP_REPLY

class DiscoverPacket(RequestPacket):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_option(DHCPMessageOption(DISCOVER))
