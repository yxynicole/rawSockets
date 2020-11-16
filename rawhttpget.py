#! /usr/bin/python

import sys, socket, time
from struct import *

def main():
	if (len(sys.arg) < 2):
		print("Please specify an URL")
		sys.exit(1)

	url = sys.argv[1]

	print('Requesting url', url)

	content = http_get(url)
	filename = url.split('/')[-1] or "index.html"
	with open (filename, 'w') as f:
		f.write(content)


# checksum functons needed for calculation checksum
def checksum(msg):
	s = 0
	
	# loop taking 2 characters at a time
	for i in range(0, len(msg), 2):
		w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
		s = s + w
	
	s = (s>>16) + (s & 0xffff);
	s = s + (s >> 16);
	
	#complement and mask to 4 byte short
	s = ~s & 0xffff
	return s


def get_ip_header(source_ip, dest_ip):
	
	# ip header fields
	ip_ihl = 5
	ip_ver = 4
	ip_tos = 0
	ip_tot_len = 0	# kernel will fill the correct total length
	ip_id = 54321	#Id of this packet
	ip_frag_off = 0
	ip_ttl = 255
	ip_proto = socket.IPPROTO_TCP
	ip_check = 0	# kernel will fill the correct checksum
	ip_saddr = socket.inet_aton ( source_ip )	#Spoof the source ip address if you want to
	ip_daddr = socket.inet_aton ( dest_ip )

	ip_ihl_ver = (ip_ver << 4) + ip_ihl

	# return ip_header.The ! in the pack format string means network order, 
	return pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)


def get_tcp_header(source_ip, dest_ip, user_data):
	
	# tcp header fields
	tcp_source = 1234	# source port
	tcp_dest = 80	# destination port
	tcp_seq = 454
	tcp_ack_seq = 0
	tcp_doff = 5	#4 bit field, size of tcp header, 5 * 4 = 20 bytes
	
	#tcp flags
	tcp_fin = 0
	tcp_syn = 1
	tcp_rst = 0
	tcp_psh = 0
	tcp_ack = 0
	tcp_urg = 0
	tcp_window = socket.htons (5840)	#	maximum allowed window size
	tcp_check = 0
	tcp_urg_ptr = 0

	tcp_offset_res = (tcp_doff << 4) + 0
	tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

	# the ! in the pack format string means network order
	tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

	source_address = socket.inet_aton(source_ip)
	dest_address = socket.inet_aton(dest_ip)
	placeholder = 0
	protocol = socket.IPPROTO_TCP
	tcp_length = len(tcp_header) + len(user_data)

	psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
	psh = psh + tcp_header + user_data;
	tcp_check = checksum(psh)
	print("-----Checksum: ", tcp_check) 

    # pseudo header fields
    source_address = socket.inet_aton( source_ip ) 
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)

    psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
    psh = psh + tcp_header + user_data;

    tcp_check = checksum(psh)
    #print tcp_checksum

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    return tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)

def get_http(url):
	#create a raw socket
    try:
        s_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as e:
        print(e)
        sys.exit(1)

    try: 
    	s_rev = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except socket.error as e:
        print(e)
        sys.exit(1)

    source_ip = socket.gethostbyname(socket.gethostname())
    print("Local IP ", source_ip)

    dest_ip = (url.split('/')[2])
    print("Remote IP: ", dest_ip)

    s_rev.bind((socket.htonl(''),0))	# unsure!

    user_data = b`"Hello, how are you?"
    ip_header = get_ip_header(source_ip, dest_ip)
    tcp_header = get_tcp_header(source_ip, dest_ip, user_data)

    # final full packet - syn packets dont have any data
    packet = ip_header + tcp_header + user_data

    print('sending packet...')
    s_send.sendto(packet, (dest_ip , 80))
    print('sent')
    s_rev.recov(1024)

if __name__ == "__main__":
	main()	