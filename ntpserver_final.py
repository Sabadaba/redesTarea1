import socket
import struct
import sys
import datetime
import time
import zlib

NTPFORMAT = "!B B B b 11I"
NTP_DELTA = 2208988800.0

def _to_int(timestamp):
        return int(timestamp)


def _to_frac(timestamp, bits=32):
        return int(abs(timestamp - _to_int(timestamp)) * 2**bits)

def _to_time(integ, frac, bits=32):
        return integ + float(frac)/2**bits

def system_to_ntp_time(timestamp):
        ntp_time = timestamp + NTP_DELTA
        return ntp_time


def ntp_to_system_time(timestamp):
        return timestamp - NTP_DELTA        

class NTPPacket(object):
    _PACKET_FORMAT = "!B B B b 11I"
    """packet format to pack/unpack"""

    def __init__(self, version=2, mode=3, tx_timestamp=0):
        self.leap = 0
        """leap second indicator"""
        self.version = version
        """version"""
        self.mode = mode
        """mode"""
        self.stratum = 0
        """stratum"""
        self.poll = 0
        """poll interval"""
        self.precision = 0
        """precision"""
        self.root_delay = 0
        """root delay"""
        self.root_dispersion = 0
        """root dispersion"""
        self.ref_id = 0
        """reference clock identifier"""
        self.ref_timestamp = 0
        """reference timestamp"""
        self.orig_timestamp = 0
        """originate timestamp"""
        self.recv_timestamp = 0
        """receive timestamp"""
        self.tx_timestamp = tx_timestamp
        """transmit timestamp"""

    def to_data(self):
        packed = struct.pack(
                        NTPPacket._PACKET_FORMAT,
                        (self.leap << 6 | self.version << 3 | self.mode),
                        self.stratum,
                        self.poll,
                        self.precision,
                        _to_int(self.root_delay) << 16 | _to_frac(self.root_delay, 16),
                        _to_int(self.root_dispersion) << 16 |
                        _to_frac(self.root_dispersion, 16),
                        self.ref_id,
                        _to_int(self.ref_timestamp),
                        _to_frac(self.ref_timestamp),
                        _to_int(self.orig_timestamp),
                        _to_frac(self.orig_timestamp),
                        _to_int(self.recv_timestamp),
                        _to_frac(self.recv_timestamp),
                        _to_int(self.tx_timestamp),
                        _to_frac(self.tx_timestamp))
        return packed


    def from_data(self, data):
        try:
                unpacked = struct.unpack(
                        NTPPacket._PACKET_FORMAT,
                        data[0:struct.calcsize(NTPPacket._PACKET_FORMAT)]
                )
        except struct.error:
                raise Exception()      
        self.leap = unpacked[0] >> 6 & 0x3
        self.version = unpacked[0] >> 3 & 0x7
        self.mode = unpacked[0] & 0x7
        self.stratum = unpacked[1]
        self.poll = unpacked[2]
        self.precision = unpacked[3]
        self.root_delay = float(unpacked[4])/2**16
        self.root_dispersion = float(unpacked[5])/2**16
        self.ref_id = unpacked[6]
        self.ref_timestamp = _to_time(unpacked[7], unpacked[8])
        self.orig_timestamp = _to_time(unpacked[9], unpacked[10])
        self.recv_timestamp = _to_time(unpacked[11], unpacked[12])
        self.tx_timestamp = _to_time(unpacked[13], unpacked[14])


localIP     = "192.168.1.114"
localPort   = 9000
bufferSize  = struct.calcsize(NTPFORMAT)


def sacar_precision():
        try:
                hz = int(1 / time.clock_getres(time.CLOCK_REALTIME))
        except AttributeError:
                hz = 1000000000
        precision = 0
        while hz > 1:
                precision -= 1
                hz >>= 1
        return precision

# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
# Bind to address and ip
UDPServerSocket.bind((localIP, localPort))
print("Link Available")

# Listen for incoming datagrams

while(True):
        try:
                # receive the query
                packet, addr = UDPServerSocket.recvfrom(1024)
                print("Link busy")
                time.sleep(2)
                serverrecv = system_to_ntp_time(time.time())
                udp_header = packet[:16]
                data = packet[16:]
                udp_header = struct.unpack("!IIII", udp_header)
                correct_checksum = udp_header[3]
                checksum = zlib.crc32(data)
                if correct_checksum == checksum:
                        recvPacket = NTPPacket(mode=3,version=2,tx_timestamp=0)
                        recvPacket.from_data(data)
                        if recvPacket.mode == 3:
                                sendPacket = NTPPacket(version=3,mode=4)
                        else: 
                                sendPacket = NTPPacket(version=3,mode=2)        
                        if recvPacket.leap == 3:
                                print("Client not synchronized")
                                sendPacket.leap = 3
                                sendPacket.recv_timestamp = 0
                                sendPacket.orig_timestamp = recvPacket.tx_timestamp
                                sendPacket.ref_timestamp = 0
                                reference = system_to_ntp_time(time.time())
                        else:
                                print("Client already synchronized")
                                orig_time= recvPacket.tx_timestamp   
                                sendPacket.leap = 0
                                sendPacket.recv_timestamp = serverrecv
                                sendPacket.orig_timestamp = orig_time
                                sendPacket.ref_timestamp = reference
                        sendPacket.stratum = 1
                        sendPacket.version = recvPacket.version
                        sendPacket.poll = recvPacket.poll
                        sendPacket.precision = sacar_precision()
                        sendPacket.tx_timestamp = system_to_ntp_time(time.time())
                        data = sendPacket.to_data()
                        checksum = zlib.crc32(data)
                        udp_header = struct.pack("!IIII", localPort, addr[1], bufferSize, checksum)
                        PacketandHeader = udp_header + data
                        UDPServerSocket.sendto(PacketandHeader, addr)
                        print("Packet sent")
                else:
                        print("Corrupt Packet")        
        except:
                print("An error has ocurred")
                pass



