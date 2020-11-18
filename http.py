import socket
from ConnectionUtils import recv, send, filter_message
import config
from handshake import close_connection

def http_get(s_sock, r_sock, hostname, path, src_ip, dest_ip, s_ip_header, s_tcp_header):
    if config.DEBUG:
        print('Sending Get Request to host:', hostname, 'path:', path)
    http_header = get_http_header(path, hostname)

    s_tcp_header.set_flags(ack_flag=1, psh_flag=1)
    s_tcp_header.data = http_header
    
    send(s_sock, dest_ip, s_ip_header, s_tcp_header)

    resp = collect_data(s_sock, r_sock, src_ip, dest_ip, s_ip_header, s_tcp_header)

    return resp


def get_http_header(path, hostname):
    return b"\r\n".join([
        b"GET {} HTTP/1.1".format(path),
        b"Host: {}".format(hostname),
        b"Connection: keep-alive", b"", b""
    ])


def collect_data(s_sock, r_sock, src_ip, dest_ip, s_ip_header, s_tcp_header):
    
    s_tcp_header.data = '' # clear http header
    s_tcp_header.set_flags(ack_flag=1) # rest of packet should be ack only

    r_ip_header, r_tcp_header, data = recv(r_sock)
    seq_expected = r_tcp_header.seq_num + len(data)
    ack_expected = r_tcp_header.ack_num
    raw_messages = [data]

    while True:
        r_ip_header, r_tcp_header, data = recv(r_sock)
        if filter_message(r_ip_header, r_tcp_header, src_ip, dest_ip, seq_expected, ack_expected):
            if config.DEBUG: print("user data sample", "*"*50, data[:20], data[-20:])
            raw_messages.append(data)
            ack_expected = s_tcp_header.seq_num = r_tcp_header.ack_num
            seq_expected = s_tcp_header.ack_num =  r_tcp_header.seq_num + len(data)
            s_tcp_header.set_flags(ack_flag=1)
            if 1 & r_tcp_header.flags: # finish flag
                close_connection(s_sock, r_sock, dest_ip, s_ip_header, s_tcp_header)
                break
            send(s_sock, dest_ip, s_ip_header, s_tcp_header)

    return ''.join(raw_messages)
