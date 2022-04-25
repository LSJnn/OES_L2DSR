import sys
from scapy.all import *
import sqlite3
import threading

## lg     88-36-6c-f7-4e-d2 192.168.100.47
## L2DSR  70-5D-CC-FC-25-02 192.168.100.214
## git서버 70-5D-CC-F4-66-9A 192.168.100.49

##패킷 생성
count = 1
router_mac = '70:5D:cc:fc:25:02'
server_mac = '70:5d:cc:f4:66:9a'
protocol_type = 'tcp'
sniffing_time = 2
maclist = []

def ConnectDB():
    global con
    con = sqlite3.connect("./DB/OE_L2DSR",isolation_level=None)

def SelectMac():
    global maclist
    c = con.cursor()

    sql = "SELECT mac from TB_MAC"
    c.execute(sql)
    maclist = [item[0] for item in c.fetchall()]

def Sniffing():
    global count
    # and dst 70:5d:cc:fc:25:02
    pcap_file = sniff(prn=ShowPacket, filter="tcp and ether dst 70:5d:cc:fc:25:02")
    if count == 1:
        print("No Packet")
        sys.exit()
    else:
        print("Total Packet: %s" % (count - 1))

def ShowPacket(packet):
    #global count = 1
    #ControlPacket(packet)
    t=threading.Thread(target=ControlPacket,args=(packet))
    print("THREAD ="+str(t.name))
    t.start()

def ControlPacket(packet):
    global count
    global maclist
    sniff_maclist = maclist
    src_mac = packet.src
    dst_mac = packet.dst

    # if src_mac=="88:36:6c:f7:4e:d2" :
    #     a= str(sniff_maclist[0])
    #     if src_mac==a:
    #         print("same")
    #     else :
    #         print("not same")

    if src_mac not in sniff_maclist :
        #db update
        sniff_maclist = maclist
    else:
        print("Success")
        packet.dst=server_mac
        print("packet src %s packet dst %s" % (packet.src, packet.dst))
        # packet.show()
        # print("ss======")
        sendp(packet)
        # ls(packet)
        # print("ss======")
    print(count)
    count += 1

ConnectDB()
SelectMac()
Sniffing()

