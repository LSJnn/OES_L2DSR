import sys
from scapy.all import *
import sqlite3
import threading
import select
import socket
from collections import deque

## lg     88:36:6c:f7:4e:d2 192.168.100.47
## L2DSR  70:5d:cc:fc:25:02 192.168.100.214
          #'70:5d:cc:f4:88:9a' 192.168.100.49
## GH 임시 서버 b0:7b:25:07:f7:cc 192.168.100.44


##패킷 생성
count = 1
server_mac = '70:5d:cc:fc:25:02'
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
    while(1) :
        print("start t1_1 대기중")
        pcap_file = sniff(prn=QueSocket, count=1, filter='dst port 80 and tcp and ether dst %s' % server_mac)
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
    dest_ip = packet['IP'].dst

    if src_mac not in sniff_maclist :
        print("FAIL")
        dest_port = '52523'
        inst = PortFowarding(80, dest_ip, dest_port)
        print("FAIL : "+str(inst.dest_port))
        inst.init()
        inst.service()
        #db update
        sniff_maclist = maclist
    else:
        print("Success")
        dest_port = '52892'
        inst = PortFowarding(80, dest_ip, dest_port)
        print("SUCCESS : "+str(inst.dest_port))
        inst.init()
        inst.service()

#########################################################PF###############################################
class Forwarding(threading.Thread):
    def __init__(self, _source_conn):
        threading.Thread.__init__(self)
        self.source_conn = _source_conn
        self.dest_conn = None

    def __del__(self):
        if self.source_conn:
            self.source_conn.close()
            self.source_conn = None

        if self.dest_conn:
            self.dest_conn.close()
            self.dest_conn = None

        print('call __del__()')

    def init(self, _dest_ip, _dest_port):
        try :
            self.dest_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.dest_conn.connect((_dest_ip, _dest_port))
        except:
            return False
        return True

    def run(self):
        try :
            while True :
                i, _, _ = select.select([self.source_conn, self.dest_conn],[],[],1)

                if self.source_conn in i :
                    data = self.source_conn.recv(1024)

                    if not data :
                        print('disconnect by source_conn')
                        return
                    sendn = self.dest_conn.send(data)
                    print('S->D| send [{0}]'.format((sendn)))

                if self.dest_conn in i :
                    data=self.dest_conn.recv(1024)

                    if not data :
                        print('disconnect by source_conn')
                    sendn = self.source_conn.send(data)
                    print ('S<-D send[{0}]0'.format(sendn))
        except :
            print ("flow - except")
            return

class PortFowarding(object):
    def __init__(self, _source_port, _dest_ip, _dest_port):
        self.listen_port = int(_source_port)
        self.dest_ip = _dest_ip
        self.dest_port = int(_dest_port)

        self.sock = None

    def init(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('',self.listen_port))
        self.sock.listen(5)

    def service(self):
        list_sockets = []
        while True:
            i, _, _ = select.select(list_sockets + [self.sock], [], [], 5)

            if self.sock in i:
                conn, addr = self.sock.accept()
                print ('ACCEPT {0}'.format(addr))

                f = Forwarding(conn)

                if not f.init(self.dest_ip, self.dest_port):
                    print ('Forwarding init() failed')
                    continue

                f.start()

            print('in service...')
######################################################### MAIN ###############################################
    # if len(sys.argv) != 3:
    #     print('Invaild argument')
    #     print('ex) python port_forwarding.py [source] [dest]')
    #     print('ex) python port_forwarding.py 13306 192.168.10.188:3306')
    #     sys.exit()

    # dest_ip = sys.argv[2].split(':')[0]
    # dest_port = sys.argv[2].split(':')[1]
    #
    # inst = PortFowarding(80, dest_ip, dest_port)
    #
    # inst.init()
    # inst.service()

ConnectDB()
SelectMac()
PacketThread()
SendPacketThread()



 # while(1):
 #     Sniffing()
####### 스레드 없이 진행 .
