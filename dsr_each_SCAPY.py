import socket
import sys
from scapy.all import *
import sqlite3
import threading
from collections import deque

## lg     88-36-6c-f7-4e-d2 192.168.100.47
## L2DSR  70-5D-CC-FC-25-02 192.168.100.214
## git서버 70-5D-CC-F4-66-9A 192.168.100.49


##패킷 생성
count = 1
router_mac = '70:5d:cc:fc:25:02'
server_mac = '70:5d:cc:f4:66:9a'
protocol_type = 'tcp'
sniffing_time = 2
maclist = []
dq = deque()
serverSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

#### DB ####
def ConnectDB():
    global con
    con = sqlite3.connect("./DB/OE_L2DSR",isolation_level=None)

def SelectMac():
    global maclist
    c = con.cursor()

    sql = "SELECT mac from TB_MAC"
    c.execute(sql)
    maclist = [item[0] for item in c.fetchall()]
####  DB ####


##QUE APPEND
def PacketThread():
    t=threading.Thread(target=Sniffing)
    t.start()

def Sniffing():
    while(1):
        pcap_file = sniff(prn=QueSocket,count=1,filter="tcp and ether dst %s" %router_mac)

def QueSocket(socket):
    global dq
    dq.appendleft(socket)
    print("넣음")

##QUE POP
def SendPacketThread():
    t=threading.Thread(target=PopSocket)
    t.start()

def PopSocket():
    while(1) :
        if(dq.__len__() >0):
            packet = dq.pop()
            ControlPacket(packet)

def ControlPacket(packet):
    s=conf.L2socket
    global maclist
    sniff_maclist = maclist
    src_mac = packet.src
    dst_mac = packet.dst

    if src_mac not in sniff_maclist :
        #db update
        sniff_maclist = maclist
    else:
        print("Success")
        packet.dst=server_mac
        s.send(packet)
        #sendp(packet,socket=conf.L2socket)
        # sendpfast(packet,mbps=1000, loop=50000)
    #sys.exit()



ConnectDB()
SelectMac()
PacketThread()
SendPacketThread()



 # while(1):
 #     Sniffing()
####### 스레드 없이 진행 .
