from ip_header import *
from tcp_header import *

import socket
from struct import *

def main():

    #create a raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error:
        print("Error creating socket")
        sys.exit()

    # Tells kernel not to put in headers
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    ip_header = IpHeader()
    tcp_header = TcpHeader()

    ip_header_packed = ip_header.pack_data()
    tcp_header_packed = tcp_header.pack_data()
    packet = ip_header_packed + tcp_header_packed

    print("getting here")

    s.sendto(packet, ('52.70.229.197',0))

    print("end")

main()