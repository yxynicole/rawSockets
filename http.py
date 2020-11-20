import socket, sys, time
from ConnectionUtils import recv, send
import config
from handshake import close_connection
from collections import deque

EOF = '0\r\n\r\n'
MAX_CWND = 1000 # max congestion window
CWND = 1 # congestion window


def http_get(s_sock, r_sock, hostname, path, src_ip, dest_ip, s_ip_header, s_tcp_header):
    print('Request to - http://{}{}'.format(hostname, path))
    http_header = get_http_header(path, hostname)

    s_tcp_header.set_flags(ack_flag=1, psh_flag=1)
    s_tcp_header.data = http_header

    send(s_sock, dest_ip, s_ip_header, s_tcp_header)

    resp = collect_data(s_sock, r_sock, src_ip, dest_ip, s_ip_header, s_tcp_header)

    sep = resp.index('\r\n\r\n')
    header = resp[:sep]
    if'200 OK' not in header:
        print('Unsuccessful request- {}'.format(header))
        sys.exit(1)
    resp = resp[sep+4:]
    if resp.endswith(EOF):
        resp = resp[:-5]

    return resp


def get_http_header(path, hostname):
    return b"\r\n".join([
        b"GET {} HTTP/1.1".format(path),
        b"Host: {}".format(hostname),
        b"Accept: */*",
        b"Accept-Encoding: identity"
        b"Connection: keep-alive", b"", b""
    ])


def collect_data(s_sock, r_sock, src_ip, dest_ip, s_ip_header, s_tcp_header):
    
    s_tcp_header.data = '' # clear http header
    s_tcp_header.set_flags(ack_flag=1) # rest of packet should be ack only

    r_ip_header, r_tcp_header, data = recv(r_sock)
    seq_expected = r_tcp_header.seq_num + len(data)
    ack_expected = r_tcp_header.ack_num
    raw_message = data

    header_loaded = False
    last_recv_time = time.time()
    while True:
        r_ip_header, r_tcp_header, data = recv(r_sock)
        if filter_message(r_ip_header, r_tcp_header, src_ip, dest_ip, seq_expected, ack_expected):
            if CWND < MAX_CWND:
                CWND += 1
            if r_tcp_header.seq_num == seq_expected:
                if config.DEBUG: print("user data sample", "*"*50, data[:20], data[-20:])
                raw_message += data
                if not header_loaded:
                    if '\n' in raw_message:
                        header_loaded = True
                        if'200 OK' not in raw_message:
                            print('Unsuccessful request- {}'.format(raw_message.split('\n')[0]))
                            close_connection(s_sock, r_sock, dest_ip, s_ip_header, s_tcp_header)
                            sys.exit(1)

                ack_expected = s_tcp_header.seq_num = r_tcp_header.ack_num
                seq_expected = s_tcp_header.ack_num =  r_tcp_header.seq_num + len(data)
                s_tcp_header.set_flags(ack_flag=1)
                if 1 & r_tcp_header.flags: # finish flag
                    close_connection(s_sock, r_sock, dest_ip, s_ip_header, s_tcp_header)
                    break
                if data.endswith(EOF):
                    close_connection(s_sock, r_sock, dest_ip, s_ip_header, s_tcp_header)
                    break

                send(s_sock, dest_ip, s_ip_header, s_tcp_header)
            else:
                CWND = 1
                # request to resend since missing / out of order
                send(s_sock, dest_ip, s_ip_header, s_tcp_header)
        # timeout
        if last_recv_time + config.CONNECTION_TIMEOUT < time.time():
            print('Request Timeout')
            close_connection(s_sock, r_sock, dest_ip, s_ip_header, s_tcp_header)
            sys.exit(1)
    return raw_message


def filter_message(ip_header, tcp_header, src_ip, dest_ip, seq_expected, ack_expected):
    return all([
        ip_header.src_ip == dest_ip,
        ip_header.dest_ip == src_ip,
        tcp_header.ack_num== ack_expected,
        config.SRC_PORT == tcp_header.dest_port,
    ])
