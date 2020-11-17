import socket
from ConnectionUtils import recv, send
import config

def http_get(s_sock, r_sock, hostname, path, src_ip, dest_ip, s_ip_header, s_tcp_header):

    http_header = get_http_header(path, hostname)

    s_tcp_header.set_flags(ack_flag=1, psh_flag=1)
    s_tcp_header.data = http_header
    
    send(s_sock, dest_ip, s_ip_header, s_tcp_header)

    resp = collect_data(s_sock, r_sock, src_ip, dest_ip, s_ip_header, s_tcp_header)

    return resp


def get_http_header(path, hostname):
    return "\r\n".join([
        "GET {} HTTP/1.1".format(path),
        "Host: {}".format(hostname),
        "Connection: keep-alive", "", ""
    ])


def collect_data(s_sock, r_sock, src_ip, dest_ip, s_ip_header, s_tcp_header):
    
    s_tcp_header.data = '' # clear http header

    r_ip_header, r_tcp_header, data = recv(r_sock)
    seq_expected = r_tcp_header[2] + len(data)
    ack_expected = r_tcp_header[3]
    raw_message = data
    try:
    	while True:
	        r_ip_header, r_tcp_header, data = recv(r_sock)
	        if filter_message(r_ip_header, r_tcp_header, src_ip, dest_ip, seq_expected, ack_expected):
	            raw_message += data
	            ack_expected = s_tcp_header.seq_num = r_tcp_header[3]
	            seq_expected = s_tcp_header.ack_num =  r_tcp_header[2] + len(data)
	            s_tcp_header.set_flags(ack_flag=1)
	            send(s_sock, dest_ip, s_ip_header, s_tcp_header)

    except:
        print raw_message

    return raw_message

def filter_message(ip_header, tcp_header, src_ip, dest_ip, seq_expected, ack_expected):
    if config.DEBUG: print('seq-ack', tcp_header[2:4], seq_expected, ack_expected, 'flag', tcp_header[4])
    return all([
        ip_header[8] == dest_ip,
        ip_header[9] == src_ip,
        tcp_header[2] == seq_expected,
        tcp_header[3] == ack_expected,
        config.SRC_PORT == tcp_header[1],
        not(1 & tcp_header[5]) # finish flag
    ])
