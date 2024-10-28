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

        if ethernet_protocol == '\x08\x06': # ARP packets
            arp_header = packet[0][14:42]
            arp_detailed = unpack("2s2s1s1s2s6s4s6s4s", arp_header)

            print("****************_ETHERNET_FRAME_****************")
            print("Dest MAC:        ", binascii.hexlify(ethernet[0]))
            print("Source MAC:      ", binascii.hexlify(ethernet[1]))
            print("Type:            ", binascii.hexlify(ethernet_protocol))
            print("************************************************")
            print("******************_ARP_HEADER_******************")
            print("Hardware type:   ", binascii.hexlify(arp_detailed[0]))
            print("Protocol type:   ", binascii.hexlify(arp_detailed[1]))
            print("Hardware size:   ", binascii.hexlify(arp_detailed[2]))
            print("Protocol size:   ", binascii.hexlify(arp_detailed[3]))
            print("Opcode:          ", binascii.hexlify(arp_detailed[4]))
            print("Source MAC:      ", binascii.hexlify(arp_detailed[5]))
            print("Source IP:       ", socket.inet_ntoa(arp_detailed[6]))
            print("Dest MAC:        ", binascii.hexlify(arp_detailed[7]))
            print("Dest IP:         ", socket.inet_ntoa(arp_detailed[8]))

            print('sending ARP packet.')
            rawSocket2 = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
            rawSocket2.bind(("ath0", 0x0806))
            eth_hdr = pack("!6s6sH", binascii.hexlify(ethernet[1]), binascii.hexlify(ethernet[0]), 0x0806)

            src_ip = socket.inet_aton(socket.inet_ntoa(arp_detailed[8]))
            dst_ip = socket.inet_aton(socket.inet_ntoa(arp_detailed[6]))
            arp_hdr = pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, binascii.hexlify(ethernet[0]), src_ip, binascii.hexlify(ethernet[1]), dst_ip)

            packet = eth_hdr + arp_hdr
            rawSocket2.send(packet)