import socket
import struct
import sys
import datetime
import time
import zlib

NTPFORMAT = "!B B B b 11I"
TIME1970 = 2208988800
serverAddressPort   = ("192.168.1.120", 12000)
bufferSize          = struct.calcsize(NTPFORMAT)

def _to_int(timestamp):
        return int(timestamp)


def _to_frac(timestamp, bits=32):
        return int(abs(timestamp - _to_int(timestamp)) * 2**bits)

def _to_time(integ, frac, bits=32):
        return integ + float(frac)/2**bits

def system_to_ntp_time(timestamp):
        ntp_time = timestamp + NTP.NTP_DELTA
        return ntp_time


def ntp_to_system_time(timestamp):
        return time.ctime(timestamp - NTP.NTP_DELTA)        


class NTP:
        
        _SYSTEM_EPOCH = datetime.datetime(*time.gmtime(0)[0:3])
        """system epoch"""
        _NTP_EPOCH = datetime.datetime(1900, 1, 1)
        """NTP epoch"""
        NTP_DELTA = int((_SYSTEM_EPOCH - _NTP_EPOCH).total_seconds())
        """delta between system and NTP time"""

        LE1 = {
                0: "no warning",
                1: "last minute of the day has 61 seconds",
                2: "last minute of the day has 59 seconds",
                3: "unknown (clock unsynchronized)",
        }

        STRATUM = {
                0: "unspecified or invalid (%s)",
                1: "primary reference (%s)",
                range(2,16) : "secondary reference (via NTP or SNTP)",
                range(16,256): "reserved"
        }

        STRATUM_CODE = {
                0: "ascii",
                1: "1 Atom, VLF, callsign, LORC, GOES, GPS",
                2: "address"
        }
        MODE = {
                0: "reserved",
                1: "symmetric active",
                2: "symmetric passive",
                3: "client",
                4: "server",
                5: "broadcast",
                6: "reserved for NTP control messages",
                7: "reserved for private use",
                }

class NTPPacket(object):
    _PACKET_FORMAT = "!B B B b 11I"

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
        self.poll = unpacked[2]
        self.precision = unpacked[3]
        self.root_delay = float(unpacked[4])/2**16
        self.root_dispersion = float(unpacked[5])/2**16
        self.ref_id = unpacked[6]
        self.ref_timestamp = _to_time(unpacked[7], unpacked[8])
        self.orig_timestamp = _to_time(unpacked[9], unpacked[10])
        self.recv_timestamp = _to_time(unpacked[11], unpacked[12])
        self.tx_timestamp = _to_time(unpacked[13], unpacked[14])


def sntp_client(query_packet,sincro):

        UDPServerSocket = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
        UDPServerSocket.settimeout(5)
        try:
                # create the request packet - mode 3 is client
                if sincro != True:
                        query_packet.leap = 3
                else:
                        query_packet.leap = 0      
                packet = query_packet.to_data()
                checksum = zlib.crc32(packet)

                udp_header = struct.pack("!IIII", 1024, serverAddressPort[1], bufferSize, checksum)
                PacketandHeader = udp_header + packet
                UDPServerSocket.sendto(PacketandHeader, serverAddressPort)
                # wait for the response - check the source address
                src_addr = (None,)
                while src_addr[0] != serverAddressPort[0]:
                        response_packet, src_addr = UDPServerSocket.recvfrom(1024)                  
                # build the destination timestamp
                dest_timestamp = system_to_ntp_time(time.time())
        except: 
                print("error")
                socket.timeout(10)
        finally:
                UDPServerSocket.close()

        udp_header = response_packet[:16]
        data = response_packet[16:]
        udp_header = struct.unpack("!IIII", udp_header)
        correct_checksum = udp_header[3]
        checksum = zlib.crc32(data)
        if correct_checksum == checksum:
                query_packet.from_data(data)    
                if query_packet.leap == 0:
                        c =((query_packet.recv_timestamp - query_packet.orig_timestamp) +(query_packet.tx_timestamp - dest_timestamp))/2
                        d = ((dest_timestamp - query_packet.orig_timestamp) -(query_packet.tx_timestamp - query_packet.recv_timestamp))
                        if query_packet.leap in NTP.LE1:
                                print("Leap: ",NTP.LE1[query_packet.leap])
                        if query_packet.mode in NTP.MODE:
                                print("Modo: ",NTP.MODE[query_packet.mode])
                        if query_packet.stratum in NTP.STRATUM:
                                print("Stratum: ",NTP.STRATUM[query_packet.stratum] % query_packet.stratum)
                        if query_packet.ref_id in NTP.STRATUM_CODE:
                                print("Reference Clock Identifier: ", NTP.STRATUM_CODE[query_packet.ref_id])                
                        print("El offset del paquete es: ",c)
                        print("El delay del paquete es: ",d)
                        print("La precision del paquete es :",query_packet.precision)
                        print("El root delay es: ",query_packet.root_delay)
                        print("El root dispersion es: ", query_packet.root_dispersion)
                        print("REFERENCE TIMESTAMP: ",ntp_to_system_time(query_packet.ref_timestamp))
                        print("ORIGINATE TIMESTAMP: ",ntp_to_system_time(query_packet.orig_timestamp))
                        print("RECEIVED TIMESTAMP: ",ntp_to_system_time(query_packet.recv_timestamp))
                        print("TRANSMIT TIMESTAMP: ",ntp_to_system_time(query_packet.tx_timestamp))
                        print("DESTINATION TIMESTAMP: ", ntp_to_system_time(dest_timestamp))
                else:
                        print("Cliente sincronizado")
        else:
                print("Ocurrio una corrupcion en el paquete recibido")
        return query_packet

F = True
sincro = False
data = NTPPacket(mode=3,version=2,tx_timestamp=system_to_ntp_time(time.time()))
while(F==True):
        data = sntp_client(data,sincro)
        sincro = True
        flag = input("¿Continuar?: (escriba N para parar): ")
        if flag == "n" or flag == "N":
                F=False




