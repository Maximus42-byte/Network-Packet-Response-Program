import socket
from struct import *


rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
while True:
    packet = rawSocket.recvfrom(2048)

    packet = packet[0]

    ethernet_length = 14

    ethernet_header = packet[:ethernet_length]
    ethernet = unpack('!6s6sH', ethernet_header)
    ethernet_protocol = socket.ntohs(ethernet[2])
    if ethernet_protocol == 8:
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

        if protocol == 1:
            print('sending back ICMP packet.')
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind(("eth0", 0))
            s.send(packet)