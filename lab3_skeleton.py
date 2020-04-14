import socket
import struct


class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    ip_string = struct.unpack("!BBBB",raw_ip_addr)
    return '.'.join(map(str,ip_string))
    


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    src_port = struct.unpack("!H",ip_packet_payload[0:2])[0] #to get the int port number
    dst_port = struct.unpack("!H",ip_packet_payload[2:4])[0]
    doffset_reser_contr = ip_packet_payload[12:14]
    data_offset = (doffset_reser_contr >> 12) * 4 #word = dataoffset(4) + reserved(6) + control(6)
    payload = ip_packet_payload[data_offset:]

    return TcpPacket(src_port, dst_port, data_offset, payload)


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section

    '''in byte literals , we have 8 bits per index'''
    ver_plus_ihl = ip_packet[0] #1st byte
    ihl = (ver_plus_ihl & 0xF) * 4 #masking and converting into 32 bit words
    protocol = struct.unpack("!B",ip_packet[9])[0] #(6,) -> 6
    src_addr = parse_raw_ip_addr(ip_packet[12:16])
    dst_addr = parse_raw_ip_addr(ip_packet[16:20])    
    payload = ip_packet[ihl:] #TCP packet

    return IpPacket(protocol, ihl, src_addr, dst_addr, payload)


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    tcp = 6
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW, tcp)
    while True:
        data, addr = s.recvfrom(4096)
        IPpacket = parse_network_layer_packet(data)
        TCPpacket = parse_application_layer_packet(IPpacket.payload)
        try:
            http_info = TCPpacket.payload.decode("utf-8")
        except Exception:
            print("This not a valid HTTP request/response")
        else:
            print(f'HTTP request/response : {http_info} from address : {addr}')
    
if __name__ == "__main__":
    main()
