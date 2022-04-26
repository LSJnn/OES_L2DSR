import socket
import sys
from scapy.all import *
import sqlite3
import threading
from collections import deque

## lg     88:36:6c:f7:4e:d2 192.168.100.47
## L2DSR  70:5d:cc:fc:25:02 192.168.100.214
          #'70:5d:cc:f4:88:9a' 192.168.100.49
## GH 임시 서버 b0:7b:25:07:f7:cc 192.168.100.49


##패킷 생성
count = 1
router_mac = '70:5d:cc:fc:25:02'
server_mac = 'b0:7b:25:07:f7:cc'
protocol_type = 'tcp'

maclist = []
dq = deque()

#### DB ####
def ConnectDB():
    global con
    con = sqlite3.connect("./DB/OE_L2DSR",isolation_level=None)

def SelectMac():
    print("start2")
    global maclist
    # c = con.cursor()
    #
    # sql = "SELECT mac from TB_MAC"
    # c.execute(sql)
    # maclist = [item[0] for item in c.fetchall()]
    maclist.append('70:5d:cc:f4:66:9a')
####  DB ####


##QUE APPEND
def PacketThread():
    t=threading.Thread(target=Sniffing)
    t.start()

def Sniffing():
    while(1) :
        print("start t1_1 대기중")
        pcap_file = sniff(prn=QueSocket, count=1, filter="tcp and ether dst %s" %router_mac)
        print("넣음")

def QueSocket(socket):
    global dq
    dq.appendleft(socket)

##QUE POP
def SendPacketThread():
    t=threading.Thread(target=PopSocket)
    print("start t2")
    t.start()

def PopSocket():
    global dq
    while(1) :
        if(dq.__len__() >0):
            packet = dq.pop()
            ControlPacket(packet)

def ControlPacket(packet):
    global maclist
    sniff_maclist = maclist
    src_mac = packet.src

    if src_mac not in sniff_maclist :
        #db update
        sniff_maclist = maclist
        # packet.dport=52525
        # sendp(packet)
    else:
        print("Success")
        packet.dst=server_mac
        sendp(packet)
        #sendpfast(packet,mbps=1000, loop=50000)
    #sys.exit()


#ConnectDB()
SelectMac()
PacketThread()
SendPacketThread()



 # while(1):
 #     Sniffing()
####### 스레드 없이 진행 .
