import socket, sys
from struct import *
import binascii

rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

while True:
        packet = rawSocket.recvfrom(2048)
        packet = packet[0]
        ethernet_length = 14
        ethernet_header = packet[:ethernet_length]
        ethernet = unpack('!6s6sH', ethernet_header)
        ethernet_protocol = socket.ntohs(ethernet[2])
        if ethernet_protocol == 8:  # IP Protocol
        ip_header_packed = packet[ethernet_length:20 + ethernet_length]
        ip_header = unpack('!BBHHHBBH4s4s', ip_header_packed)
        version_IHL = ip_header[0]
        version = version_IHL >> 4
        IHL = version_IHL & 0xF
        ip_header_length = IHL * 4
        Identification = ip_header[3]
        Flags_FragmentOffset = ip_header[4]
        FragmentOffset = Flags_FragmentOffset & 0B0000111111111111
        TTL = ip_header[5]
        protocol = ip_header[6]
        checksum = ip_header[7]
        s_address = socket.inet_ntoa(ip_header[8])
        d_address = socket.inet_ntoa(ip_header[9])

            if protocol == 17:
                start_point = ip_header_length + ethernet_length
                udp_header_length = 8
                udp_header_packed = packet[start_point:start_point + udp_header_length]
                udp_header = unpack('!HHHH', udp_header_packed)
                source_port = udp_header[0]
                dest_port = udp_header[1]
                length = udp_header[2]
                checksum = udp_header[3]

                if dest_port == 53:
                    dns_packed = packet[start_point + udp_header_length:start_point + udp_header_length + 4]
                    dns = unpack('!HH', dns_packed)
                    # verify if packet is dns
                    if (dns[1] & 0b11110) == 2:
                        print('answering  DNS request.')
                        message = dns.replace(" ", "").replace("\n", "")
                        server_address = (s_address, source_port)
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        try:
                            sock.sendto(binascii.unhexlify(message), server_address)
                            data, _ = sock.recvfrom(4096)
                        finally:
                            sock.close()
