from TCPPacket import *
from IPHeader import *
from ConnectionUtils import *
import binascii

SENDER_PORT = 4567 #Randomly picked number, doesn't have special significance 
RECEIVER_IP_ADDRESS = '204.44.192.60' #course home page
STARTING_SEQ_NUM = 500 #randomly picked number 

if __name__=='__main__':
  
    sender_socket = create_send_socket()
    receiver_socket = create_receiver_socket()

    sender_ip_address = get_sender_IP_address()
    print(sender_ip_address)

    # Tells kernel not to put in headers
    sender_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Send initial syn as part of TCP three-way handshake
    ip_header = IpHeader(sender_ip_address, RECEIVER_IP_ADDRESS).form_ip_header()
    tcp_packet = TCPPacket(SENDER_PORT, STARTING_SEQ_NUM, 0, sender_ip_address, RECEIVER_IP_ADDRESS, 1, 0, '').form_tcp_packet() #Syn flag set and no data.
    packet = ip_header + tcp_packet
    sender_socket.sendto(packet, (RECEIVER_IP_ADDRESS,0))

    # get the syn ack response from the server
    response = receiver_socket.recv(65535)
    
    #validate the IP header of the syn ack response
    if (validate_ip_header(response, RECEIVER_IP_ADDRESS, sender_ip_address) == False):
        sys.exit("invalid IP header in syn ack response in 3 way handshake") #maybe can update this to try again instead of exit
    
    #validate the TCP header of the syn ack response and get the sequence number sent by the server
    seq_num_from_server = validate_syn_ack_tcp_header(response, SENDER_PORT, STARTING_SEQ_NUM+1) #returns -1 if invalid tcp syn ack header
    if (seq_num_from_server == -1):
      sys.exit("invalid tcp syn ack header")

    #complete the 3 way handshake by sending an ack back to the server
    ip_header_ack = IpHeader(sender_ip_address, RECEIVER_IP_ADDRESS).form_ip_header()
    tcp_packet_ack = TCPPacket(SENDER_PORT, STARTING_SEQ_NUM+1, seq_num_from_server+1, sender_ip_address, RECEIVER_IP_ADDRESS, 0, 1, '').form_tcp_packet() #Ack flag set and no data
    packet_ack = ip_header_ack + tcp_packet_ack
    sender_socket.sendto(packet_ack, (RECEIVER_IP_ADDRESS,0))


    print("end")
