import sys
from scapy.all import *
import sqlite3
import threading

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

def Sniffing():
    pcap_file = sniff(prn=ControlPacket,count=1,filter="tcp and ether dst %s" %router_mac)

def ShowPacket(packet):
    t=threading.Thread(target=ControlPacket,args=packet)
    print("THREAD ="+str(t.name))
    t.start()
    print("ALIVE "+t.name+" :"+ str(t.is_alive()))
    print("Alive all :"+ str(threading.active_count()))

def ControlPacket(packet):
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
        sendp(packet)
    #sys.exit()

ConnectDB()
SelectMac()

while(1):
    Sniffing()
####### 스레드 없이 진행 .
