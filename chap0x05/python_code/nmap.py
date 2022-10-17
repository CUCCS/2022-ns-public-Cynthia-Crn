
  # -*-coding:utf-8 -*-
  #! /usr/bin/python3
import sys
from scapy.all import *
import getopt

   # 使用上述实验过程中编写的 python 代码，参数为 ip 地址, 代码扫描 80/8080/443/53 等端口
def udpscan(dst_ip, dst_timeout=10):
    dst_port = 8080
    resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port), timeout=dst_timeout)
    if (resp is None):
        print("Open|Filtered")
    elif (resp.haslayer(UDP)):
        print("Open")
    elif(resp.haslayer(ICMP)):
        if(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) == 3):
            print("Closed")
        elif(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
            print("Filtered")
        elif(resp.haslayer(IP) and resp.getlayer(IP).proto == IP_PROTOS.udp):
            print("Open")


    # udpscan('172.16.111.124', 8080)

def Xmasscan(dst_ip, timeout=10):
    dst_port = 80
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="FPU"), timeout=10)
    if (pkts is None):
        print("Open|Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif(pkts.haslayer(ICMP)):
        if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


    # Xmasscan('172.16.111.124', 80)

def finscan(dst_ip, timeout=10):
    dst_port = 80
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="F"), timeout=10)
    if (pkts is None):
        print("Open|Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif(pkts.haslayer(ICMP)):
        if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


    # finscan('172.16.111.124', 80)

def nullscan(dst_ip, timeout=10):
    dst_port = 80
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags=""), timeout=10)
    if (pkts is None):
        print("Open|Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif(pkts.haslayer(ICMP)):
        if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


    # nullscan('172.16.111.124', 80)

def tcpstealthscan(dst_ip, timeout=10):
    dst_port = 80
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="S"), timeout=10)
    if (pkts is None):
        print("Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip) /
                          TCP(dport=dst_port, flags="R"), timeout=10)
            print("Open")
        elif (pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
        elif(pkts.haslayer(ICMP)):
            if(int(pkts.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                print("Filtered")


    # tcpstealthscan('172.16.111.124', 80)


def main(argv):
  dst_ip = ''
  try:
      opts, args = getopt.getopt(argv, 'h', ['help','sF=',
      'sX=','sN=','sS=','sU='])
     
      # print("opts:{},\targs:{}".format(opts, args))
  except getopt.GetoptError:
      print('Usage:   test.py -i <inputfile> -o <outputfile>')
      sys.exit(2)
  for opt, arg in opts:
      if opt == '-h':
          print('test.py --sF/--sX/--sN/--sS/--sU <dst_ip> ')
          sys.exit()
      elif opt in ("--sF"):
          dst_ip  = arg
          finscan(dst_ip)
      elif opt in ("--sX"):
          dst_ip  = arg
          Xmasscan(dst_ip)
      elif opt in ("--sN"):
          dst_ip  = arg
          nullscan(dst_ip)
      elif opt in ("--sS"):
          dst_ip  = arg
          tcpstealthscan(dst_ip)
      elif opt in ("--sU"):
          dst_ip  = arg
          udpscan(dst_ip)


if __name__ == "__main__":
  # print(sys.argv[1:])
  main(sys.argv[1:])
