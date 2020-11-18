import random, sys

DEBUG = '--no-log' not in sys.argv

SRC_PORT = random.randint(6000, 10000) #Randomly picked number, doesn't have special significance 
DEST_PORT = 80 #http uses 80
STARTING_SEQ_NUM = random.randint(500000, 2000000) #randomly picked number 

CONNECTION_TIMEOUT = 60