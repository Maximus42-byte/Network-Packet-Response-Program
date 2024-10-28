import socket, sys
from struct import *
import binascii

def send_arp_reply(source_mac, dest_mac, source_ip, dest_ip):
    rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
    rawSocket.bind(("ath0", 0x0806))

    # Ethernet Header
    protocol = 0x0806  # 0x0806 for ARP
    eth_hdr = pack("!6s6sH", dest_mac, source_mac, protocol)

    # ARP header
    htype = 1  # Hardware_type ethernet
    ptype = 0x0800  # Protocol type TCP
    hlen = 6  # Hardware address Len
    plen = 4  # Protocol addr. len
    operation = 2  # 1=request/2=reply
    src_ip = socket.inet_aton(source_ip)
    dst_ip = socket.inet_aton(dest_ip)
    arp_hdr = pack("!HHBBH6s4s6s4s", htype, ptype, hlen, plen, operation, source_mac, src_ip, dest_mac, dst_ip)

    packet = eth_hdr + arp_hdr
    rawSocket.send(packet)


def send_udp_message(message, address, port):
    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()


def send_ether(packet, interface="eth0"):
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
  s.bind((interface, 0))
  return s.send(packet)


def run():
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
            send_arp_reply(binascii.hexlify(ethernet[0]), binascii.hexlify(ethernet[1]), socket.inet_ntoa(arp_detailed[8]), socket.inet_ntoa(arp_detailed[6]))

        elif ethernet_protocol == 8: # IP Protocol
            # Parse IP packets:
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

            # UDP packets
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
                        print('sending back DNS packet.')
                        send_udp_message(dns, s_address, source_port) # echo dns packet.


            # ICMP Packets
            elif protocol == 1:
                print('sending back ICMP packet.')
                send_ether(packet) # echo icmp packet.


# *************** main ***************

run()

# ************* end main *************
