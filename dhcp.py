#!/usr/bin/env python3 

# davep 07-Mar-2016 ; DHCP in Python for testing
#
# Never never never broadcast any packets. Only unicasts to a specific known
# server IP address. Best effort taken to not disrupt normal network operations.
#
# davep 15-Mar-2016 ; integrated my Python2 DHCP stuff from 2003 (!)
#
# https://tools.ietf.org/html/rfc2131
# https://tools.ietf.org/html/rfc2132

import struct
import random
import socket
import logging
import ipaddress

logger = logging.getLogger("dhcp")

cookie = b"\x63\x82\x53\x63"

SERVER_PORT = 67
CLIENT_PORT = 68

BOOTP_REQUEST=1
BOOTP_REPLY=2

bootp_ops = ( "invalid", "boot-request", "boot-reply" )
message_types = ( "invalid", "Discover", "Offer", "Request", "Decline", "Ack", "Nak", "Release", "Inform" )
htype_strings = { 1 : "Ethernet" }

FLAGS_BROADCAST = (1<<15)

chaddr_len = 16
sname_len = 64
bootfile_len = 128

# size of packet not including options field
basepkt_size = 236

# the most commonly used options from RFC2132
option_pad = 0
subnet_mask = 1
time_offset = 2
router = 3
time_server = 4
domain_name_server = 6
domain_name = 15
broadcast_address = 28
network_time_server = 42
netbios_name_server = 44  
requested_ip = 50
lease_time = 51
option_overload = 52
dhcpmessage = 53
serverid = 54
param_request_list = 55
err_message = 56
max_message_size = 57
renewal_time = 58
rebinding_time = 59
vendorid = 60
clientid = 61
option_end = 0xff

# fields in OPT_DHCP_MESSAGE options field
DISCOVER = 1
OFFER = 2
REQUEST = 3
DECLINE = 4
ACK = 5
NAK = 6
RELEASE = 7

class DHCPException(Exception) :
    """Base class for all exceptions raised by this module."""
    pass

class DHCPPacketError(DHCPException) :
    """The packet being decoded is not a valid DHCP packet."""
    pass

class DHCPEncodeError(DHCPException) :
    """There was an error with the parameters while building the DHCP packet."""
    pass

class DHCPTransactionError(DHCPException):
    """Error in the DHCP Transaction State Machine"""
    pass

def make_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    return sock

class Option :
    """Base class for DHCP options.  Don't use directly."""
    def __init__(self,opcode,name) :
        self.opcode = opcode
        self.name = name
        self.value = None
        # packed_option is <type> <length> <data> all struct.pack()'d together, ready 
        # for sending out on the network
        self.packed_option = b""

class IP_Option(Option) :
    """DHCP Option containing a list of IP addresses."""
    def __init__(self, opcode, name, value=None) :
        super().__init__(opcode,name)

        # want an array of IPAddress instances so let's see how it quacks
        if value is not None:
            for v in value:
                s = v.packed
        self.value = value or []

    def __str__(self) :
        if len(self.value):
            return "<{} {} {}>".format(self.opcode, self.name, \
                ",".join([socket.inet_ntoa(ip) for ip in self.value]))
        return "<{} {} (none)>".format(self.opcode, self.name)

    def new(self,value=None) :
        return IP_Option( self.opcode, self.name, value )

    def pack( self ) :
        # remember there can be more than 1 IP address in here
        self.packed_option = struct.pack( "!BB", self.opcode, len(self.value)*4) 
        self.packed_option += b''.join(ip.packed for ip in self.value)
        return self.packed_option

    def unpack(self,data) :
        # there can be more than 1 IP address in an option
        olen = data[1]
        self.value = []
        dstart = 2
        # verify we have a multiple of 4 bytes
        if olen % 4 != 0 :
            raise DHCPPacketError("IP address option length is "+str(olen)+" and not a multiple of 4")

        # now decode each ip address
        for x in range( olen // 4 ):
            ip = data[dstart:dstart+4]
            self.value.append( ip )
            dstart = dstart + 4

class Int_Option(Option) :
    """DHCP Option containing a 1, 2, or 4 byte integer."""
    def __init__(self,opcode,name,value=None) :
        super().__init__(opcode,name)
        self.value = value

    def __str__(self) :
        return "<{} {} {}>".format(self.opcode, self.name, self.value)

    def new(self,value=None) :
        return Int_Option( self.opcode, self.name, value )

    def unpack(self,data) :
        # type is [0]
        # length is [1]
        # data is [2:2+length]
        olen = data[1]
        num = data[2:2+olen]
        if len(num) == 1 :
            self.value, = struct.unpack( "B", num )
        elif len(num) == 2 :
            self.value, = struct.unpack( ">H", num )
        elif len(num) == 4 :
            self.value, = struct.unpack( ">L", num )
        else :
            raise DHCPPacketError("Invalid integer data length "+str(olen)+" for option "+hex(self.opcode))

    def pack(self) :
        if self.value <= 0xff :
            self.packed_option  = struct.pack( "BBB", self.opcode, 1, self.value )
        elif self.value <= 0xffff :
            self.packed_option = struct.pack( ">BBH", self.opcode, 2, self.value )
        elif self.value <= 0xffffffff :
            self.packed_option = struct.pack( ">BBL", self.opcode, 4, self.value )
        else :
            raise DHCPEncodeError("No support for integers larger than 4 bytes for option "+hex(self.opcode))
        return self.packed_option.encode("UTF-8")

class Int32_Option( Int_Option ) :
    """DHCP Option containing a 32-bit integer."""
    def new(self,value=None) :
        return Int32_Option( self.opcode, self.name, value )

    def unpack(self,data) :
        olen = data[1]
        if olen != 4 :
            raise DHCPPacketError("Invalid integer data length "+str(olen)+" for option "+hex(self.opcode))
        Int_Option.unpack( self, data )

    def pack(self) :
        # always pack as a 32-bit integer
        self.packed_option = struct.pack( ">BBL", self.opcode, 4, self.value )
        return self.packed_option.encode("UTF-8")

class DHCP_Message_Option( Int_Option ) :
    """DHCP Message Type Option (53)."""
    def __str__(self) :
        return "<{} {} {} \"{}\">".format(self.opcode, self.name, self.value, message_types[self.value])

    def unpack(self,data) :
        Int_Option.unpack(self,data)
        # verify we were sent a correct DHCP message
        try :
            message_types[self.value]
            if self.value == 0 :
                raise IndexError
        except IndexError:
            raise DHCPPacketError("Invalid DHCP message type "+str(self.value)+" for option "+hex(self.opcode))

    def pack( self ) :
        self.packed_option = struct.pack( "BBB", dhcpmessage, 1, self.value )
        assert type(self.packed_option)==type(b'')
        return self.packed_option

    def new( self, value=None) :
        return DHCP_Message_Option( self.opcode, self.name, value )

class Str_Option(Option) :
    """DHCP Option containing a printable string (such as domain name)."""
    def __init__(self,opcode,name,value=None) :
        if value is not None and type(value) != type(b"") :
            raise DHCPEncodeError("String option must be {} not {}".format(type(b""),type(value)))
        super().__init__(opcode,name)
        self.value = value

    def __str__(self) :
        return "<{} {} \"{}\">".format(self.opcode, self.name, self.value)

    def new( self, value=None) :
        return Str_Option( self.opcode, self.name, value )

    def unpack(self,data) :
        olen = data[1]
        self.value = data[2:2+olen]

    def pack( self ) :
        self.packed_option = struct.pack( "BB", self.opcode, len(self.value) ) + self.value
        return self.packed_option


class Hex_Option( Str_Option ) :
    """DHCP Option for strings containing unprintable characters such as clientid.
       Will be printed as a hex dump."""
    def __str__(self) :
        s = str(self.opcode) + " " + self.name + " 0x"
        for c in self.value :
            # The following code will print hex dump like:
            # \x01\x03\x06\x0c\x0f\x1c  and \x00003044000007_ppp1
            # (printable chars will be printed, unprintable printed as hex)
            """
            if ord(c) >= ord(' ') and ord(c) <= ord('~') :
                s = s + c
            else :
                s = s + "\\x%02x" % ord(c)
            """
            # I liked it better as a straight hex dump.
            s = s + "%02x" % c
        return s

    def new(self,value=None) :
        return Hex_Option( self.opcode, self.name, value )

class Unknown_Option( Hex_Option ) :
    """DHCP Option for options with unknown opcodes.  
       Will be printed as a hex dump."""
    def __init__(self,opcode) :
        super().__init__(opcode,"(unknown)")
        self.value = "" 

    # do not allow unknown objects to be cloned
    def new(self,value=None) :
        raise DHCPEncodeError("option "+str(self.opcode)+" is unknown and cannot be used.")

    def pack(self) :
        return ""

class Param_Request_Option( Hex_Option ) :
    """DHCP Option for parameter request list (58).  An easier way to handle
    parameter request list options."""
    def new(self,value=None) :
        # pack array of integers into a string
        logger.debug("param_list value=%s", value)
        # expecting a list of integers or None (list can be empty)
        self.value = value
        if value :
            value = struct.pack("{}B".format(len(value)), *value)
        return Param_Request_Option( self.opcode, self.name, value )

    def __getitem__(self, key) :
        if type(key) != type(0) :
            raise TypeError
        for s in self.value :
            if key == s :
                return s
        raise IndexError

    def __contains__(self, key): 
        if type(key) != type(0) :
            raise TypeError
        for s in self.value :
            if key == s :
                return True
        return False

# All options and option strings from RFC2132
_option_table = {    
                    1 : IP_Option( 1, "subnet mask" ),
                    2 : Int32_Option( 2, "time offset" ),
                    3 : IP_Option( 3, "router" ),
                    4 : IP_Option( 4, "time server" ),
                    6 : IP_Option( 6, "domain name server" ),
                    7 : IP_Option( 7, "log server" ),
                    8 : IP_Option( 8, "cookie server" ),
                    9 : IP_Option( 9, "LPR server" ),
                   10 : IP_Option(10, "Impress server" ),
                   11 : IP_Option(11, "resource location server" ),
                   12 : Str_Option(12, "host name" ),
                   13 : Int_Option(13, "boot file size" ),
                   14 : Str_Option(14, "merit dump file" ),
                   15 : Str_Option(15, "domain name" ),
                   16 : IP_Option(16, "swap server" ),
                   17 : Str_Option(17, "root path" ),
                   18 : Str_Option(18, "extensions path" ),
                   19 : Int_Option(19, "ip forwarding flag" ),
                   20 : Int_Option(20, "non-local source routing flag" ),
                   21 : Str_Option(21, "policy filter" ),
                   22 : Int_Option(22, "maximum datagram reassembly size" ),
                   23 : Int_Option(23, "default IP TTL" ),
                   24 : Int32_Option(24, "path MTU aging timeout" ),
                   25 : Int_Option(25, "path MTU plateau table" ),
                   26 : Int_Option(26, "interface MTU" ),
                   27 : Int_Option(27, "all subnets local flag" ),
                   28 : IP_Option(28, "broadcast address" ),
                   29 : Int_Option(29, "perform mask discovery flag" ),
                   30 : Int_Option(30, "mask supplier" ),
                   31 : Int_Option(31, "perform router discovery flag" ),
                   32 : IP_Option(32, "router solicitation address" ),
                   33 : IP_Option(33, "static route" ),
                   34 : Int_Option(34, "trailer encapsulation" ),
                   35 : Int32_Option(35, "arp cache timeout" ),
                   36 : Int_Option(36, "Ethernet encapsulation" ),
                   37 : Int_Option(37, "TCP default TTL" ),
                   38 : Int32_Option(38, "TCP keepalive interval" ),
                   39 : Int_Option(39, "TCP keeaplive garbage flag" ),
                   40 : Str_Option(40, "NIS domain" ),
                   41 : IP_Option(41, "NIS servers" ),
                   42 : IP_Option(42, "NTP servers" ),
                   43 : Hex_Option(43, "vendor specific" ),
                   44 : IP_Option(44, "NetBIOS over TCP/IP name server" ),
                   45 : IP_Option(45, "NetBIOS over TCP/IP datagram distribution server" ),
                   46 : Int_Option(46, "NetBIOS over TCP/IP node type" ),
                   47 : Str_Option(47, "NetBIOS over TCP/IP scope" ),
                   48 : IP_Option(48, "X Window font server" ),
                   49 : IP_Option(49, "X Window display manager" ),

                   # DHCP specific options
                   50 : IP_Option(50, "requested IP address" ),
                   51 : Int32_Option(51, "IP address lease time" ),
                   52 : Int_Option(52, "option overload" ),
                   53 : DHCP_Message_Option(53, "DHCP message" ),
                   54 : IP_Option(54, "server identifier" ),
                   55 : Param_Request_Option(55, "parameter request list" ),
                   56 : Str_Option(56, "error message" ),
                   57 : Int_Option(57, "max message size" ),
                   58 : Int32_Option(58, "renewal (T1) time" ),
                   59 : Int32_Option(59, "rebinding (T2) time" ),
                   60 : Hex_Option(60, "vendor id" ),
                   61 : Hex_Option(61, "client id" ),

                   64 : Str_Option(64, "NIS+ domain" ),
                   65 : IP_Option(65, "NIS+ servers" ),
                   66 : Str_Option(66, "TFTP server name" ),
                   67 : Str_Option(67, "bootfile name" ),
                   68 : IP_Option(68, "mobile IP home agent" ),
                   69 : IP_Option(69, "SMTP server" ),
                   70 : IP_Option(70, "POP3 server" ),
                   71 : IP_Option(71, "NNTP server" ),
                   72 : IP_Option(72, "default WWW server" ),
                   73 : IP_Option(73, "default finger server" ),
                   74 : IP_Option(74, "default IRC server" ),
                   75 : IP_Option(75, "StreetTalk server" ),
                   76 : IP_Option(76, "StreetTalk directory assistance server" ),
                }


# A collection class containing the DHCP options for a packet.
# Simply a wrapper around a dictionary with a nicer print function.
# http://www.python.org/doc/FAQ.html#4.2
class OptionsDict :
    def __init__(self) :
        self.options = {}
        self.packed_options = b""

    def clear( self ) : self.options.clear() 
    def __setitem__( self, key, item ) : self.options[key] = item
    def __getitem__( self, key ) : return self.options[key]
    def __contains__(self, key) : return key in self.options
    def keys( self ) : return self.options.keys()

    def __str__( self ) :
        return ", ".join([str(opt) for opt in self.options.values()])

    def unpack( self, data ) :
        self.packed_options = data 
        i = 0
        self.options.clear()
        while i < len(data) : 
            otype = data[i]

            # end of options so leave
            if otype == option_end :
                break

            # skip pad bytes
            if otype == option_pad :
                i = i+ 1
                continue

            # option length
            olen = data[i+1]

            try:
                self.options[otype] = _option_table[otype].new()
            except IndexError:
                self.options[otype] = Unknown_Option( otype )
            try :
                self.options[otype].unpack( data[i:] )
            except DHCPPacketError as err :
                raise DHCPPacketError( errstr.args[0] + "; bad option at offset "+str(i))

            # +2 to skip the option type and option length
            i = i+ olen + 2

    def pack( self ) :
        logger.info("options=%s", self.options)
        self.packed_options = cookie +\
            b''.join([opt.pack() for opt in self.options.values()]) +\
            struct.pack("B",option_end)
        return self.packed_options
        
class Packet:
    op = None 
    htype = 1
    hlen = 6 # ethernet

    fmt = ">BBBBLHH4s4s4s4s16s64s128s"
#    fmt = ">BBBBLHH16s16s64s128s"
#    fmt = ">BBBBLHHLLLL16s64s128s"
#    fmt = ">BBBBLHHLLLL16s64s128s312s"

    def __init__(self, **kwargs):
        self.buf = None
        self.hops = 0
        self.xid = kwargs.get("xid") or random.randint(0,2**32-1)
        self.secs = 0
        self.flags = 0
        self.ciaddr = ipaddress.ip_address(0)
        self.yiaddr = ipaddress.ip_address(0)
        self.siaddr = ipaddress.ip_address(0)
        self.giaddr = ipaddress.ip_address(0)
        self.chaddr = kwargs.get("chaddr", b'')
        self.sname = ""
        self.bootfile = ""

        # array of Option instances
        self.options = OptionsDict()

    def pack(self):
        self.buf = struct.pack(self.fmt,
                        # Bytes (four fields)
                        self.op, self.htype, self.hlen, self.hops,

                        # Long (uint32)
                        self.xid,

                        # sHort (uint16) (two fields)
                        self.secs, self.flags,

                        # four IP addresses in packed form
                        self.ciaddr.packed, self.yiaddr.packed, self.siaddr.packed, self.giaddr.packed,
#                        iaddr_buf,

                        # 16 byte chaddr
                        self.chaddr,

                        # 64-byte server hostname
                        self.sname.encode("UTF-8"),

                        # 128-byte boot file name
                        self.bootfile.encode("UTF-8"),
                   )
        self.buf += self.options.pack()
        return self.buf
        
    def add_option(self, option):
        self.options.add(option)

    @staticmethod
    def unpack(buf):
        if len(buf) < basepkt_size :
            raise DHCPPacketError("packet too short len={}", len(buf))

        # quick sanity check on the first byte to verify we're at least in the
        # vague general direction of DHCP
        op, = struct.unpack("B", buf[0:1])
        logger.info("op={:x} len={}".format(op, len(buf)))
        if op not in (BOOTP_REQUEST, BOOTP_REPLY):
            errmsg = ("op={:x} and is not Request or Reply".format(op))
            raise DHCPPacketError(errmsg)

        # parse the options first to decide what sort of DHCP packet this might be
        # carve off the options
        raw_options, = struct.unpack( str(len(buf)-basepkt_size)+"s", buf[basepkt_size:] )

        # verify cookie
        if len(raw_options) < 4 :
            raise DHCPPacketError("missing DHCP options cookie.")

        if raw_options[:4] != cookie : 
            raise DHCPPacketError("Bad options cookie.")

        # chop off the cookie and send in the options
        # FIXME -- need to handle options in the name and file fields
        options = OptionsDict()
        options.unpack( raw_options[4:] )
        logger.debug("options=%s", options)

        if dhcpmessage not in options:
            raise DHCPPacketError("missing DHCP Message field (opt=53)")

        msgtype = options[dhcpmessage].value
        try:
            pkt = _packet_lut[msgtype]()
        except KeyError:
            raise DHCPPacketError("invalid DHCP Message field (opt=53 value={:x})".format(msgtype))

        # now decode the front part of the packet
        (pkt.op, pkt.htype, pkt.hlen, pkt.hops, pkt.xid, pkt.secs, 
         pkt.flags, pkt.ciaddr, pkt.yiaddr, pkt.siaddr, pkt.giaddr, 
         pkt.chaddr, pkt.sname, pkt.bootfile) = \
                    struct.unpack( ">BBBBLHH4s4s4s4s16s64s128s", buf[:basepkt_size] )

        pkt.ciaddr = ipaddress.ip_address(socket.inet_ntoa(pkt.ciaddr))
        pkt.yiaddr = ipaddress.ip_address(socket.inet_ntoa(pkt.yiaddr))
        pkt.siaddr = ipaddress.ip_address(socket.inet_ntoa(pkt.siaddr))
        pkt.giaddr = ipaddress.ip_address(socket.inet_ntoa(pkt.giaddr))

        pkt.options = options
        pkt.buf = buf

        return pkt

    def set_option( self, opcode, opvalue ) :
        self.options[opcode] = _option_table[opcode].new( opvalue )

    def __str__(self) :
        try :
            s = "op:"+bootp_ops[ self.op ]
        except IndexError:
            raise DHCPPacketError("Invalid BOOTP opcode {:x}", self.op)
        
        s += "xid:{:x} flags:{:x} G:{} C:{} Y:{} S:{}".format(self.xid, self.flags, self.giaddr, self.ciaddr, self.yiaddr, self.siaddr)

#        s = s + " xid:"+hex(self.xid) + \
#            " flags:"+hex(self.flags)  + \
#            " G:"+self.giaddr + \
#            " C:"+self.ciaddr + \
#            " Y:"+self.yiaddr + \
#            " S:"+self.siaddr 

        chaddr = " chaddr:"
        i=0
        for c in self.chaddr :
            chaddr = chaddr + "%02x" % c
            i = i + 1
            if i >= self.hlen or i >= 16 :
                break
        
        s = s + chaddr
        return s


class _DHCP_Request(Packet):
    op = BOOTP_REQUEST

class _DHCP_Reply(Packet):
    op = BOOTP_REPLY

class DiscoverPacket(_DHCP_Request):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_option(dhcpmessage, DISCOVER)

class OfferPacket(_DHCP_Reply):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_option(dhcpmessage, OFFER)

class RequestPacket(_DHCP_Request):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_option(dhcpmessage, REQUEST)

class AckPacket(_DHCP_Reply):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_option(dhcpmessage, ACK)

class NakPacket(_DHCP_Reply):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_option(dhcpmessage, NAK)

class DeclinePacket(_DHCP_Request):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_option(dhcpmessage, DECLINE)

class ReleasePacket(_DHCP_Request):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_option(dhcpmessage, RELEASE)

_packet_lut = { 
    DISCOVER: DiscoverPacket,
    OFFER: OfferPacket,
    REQUEST: RequestPacket,
    DECLINE: DeclinePacket,
    ACK: AckPacket,
    NAK: NakPacket,
    RELEASE: ReleasePacket
}
