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
    seq_expected = r_tcp_header.seq_num + len(data)
    ack_expected = r_tcp_header.ack_num
    raw_messages = [data]
    try:
    	while True:
	        r_ip_header, r_tcp_header, data = recv(r_sock)
	        if filter_message(r_ip_header, r_tcp_header, src_ip, dest_ip, seq_expected, ack_expected):
	            # print("*"*50, r_tcp_header, data)
	            raw_messages.append(data)
	            ack_expected = s_tcp_header.seq_num = r_tcp_header.ack_num
	            seq_expected = s_tcp_header.ack_num =  r_tcp_header.seq_num + len(data)
	            s_tcp_header.set_flags(ack_flag=1)
	            send(s_sock, dest_ip, s_ip_header, s_tcp_header)

    except KeyboardInterrupt:
        pass

    return ''.join(raw_messages)

def filter_message(ip_header, tcp_header, src_ip, dest_ip, seq_expected, ack_expected):
    return all([
        ip_header.src_ip == dest_ip,
        ip_header.dest_ip == src_ip,
        tcp_header.seq_num == seq_expected,
        tcp_header.ack_num== ack_expected,
        config.SRC_PORT == tcp_header.dest_port,
        not(1 & tcp_header.flags) # finish flag
    ])
