from ConnectionUtils import *
import config
import time


def do_handshake(s_sock, r_sock, s_ip_header, s_tcp_header, src_ip, dest_ip):
    # first handshake
    s_tcp_header.seq_num = config.STARTING_SEQ_NUM
    s_tcp_header.ack_num = 0
    s_tcp_header.set_flags(syn_flag=1)

    send(s_sock, dest_ip, s_ip_header, s_tcp_header)

    # get the syn ack response from the server
    timeout = time.time() + config.CONNECTION_TIMEOUT
    while True:
        r_ip_header, r_tcp_header, data = recv(r_sock)
        
        #validate the IP header of the syn ack response
        if validate_ip_header(r_ip_header, dest_ip, src_ip):        
            #validate the TCP header of the syn ack response and get the sequence number sent by the server
            seq_num_from_server = validate_syn_ack_tcp_header(r_tcp_header, config.SRC_PORT, config.STARTING_SEQ_NUM+1) #returns -1 if invalid tcp syn ack header
            if seq_num_from_server != -1:
                break
            else:
                print(r_tcp_header[:4], config.SRC_PORT, config.STARTING_SEQ_NUM+1)
        if time.time() > timeout:
            print('handshake timeout')
            sys.exit(1)

    #complete the 3 way handshake by sending an ack back to the server
    s_tcp_header.seq_num = config.STARTING_SEQ_NUM + 1
    s_tcp_header.ack_num = seq_num_from_server
    s_tcp_header.set_flags(ack_flag=1)
    send(s_sock, dest_ip, s_ip_header, s_tcp_header)
    if config.DEBUG:
        print('\nConnection established')

def close_connection(s_sock, r_sock, dest_ip, s_ip_header, s_tcp_header):
    if config.DEBUG:
        print('Closing connection')

    # ack the fin flag
    s_tcp_header.set_flags(ack_flag=1)
    send(s_sock, dest_ip, s_ip_header, s_tcp_header)

    # new seq
    s_tcp_header.set_flags(fin_flag=1)
    s_tcp_header.seq_num += 1
    send(s_sock, dest_ip, s_ip_header, s_tcp_header)

    # while True:
    #     r_ip_header, r_tcp_header, _ = recv(r_sock)
    #     send(s_sock, dest_ip, s_ip_header, s_tcp_header)

    s_sock.close()
    r_sock.close()
