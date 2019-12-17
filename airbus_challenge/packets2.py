#!/usr/bin/env python

import socket

import dpkt
import collections

class ModBusTCP(dpkt.Packet):
    __hdr__ = (('id', 'BBBBB', 0),
               ('len', 'B', 0),
               ('CMD', 'B', 0),
               ('str', 'H', 0),


TCP_IP = '127.0.0.1'
TCP_PORT = 1337
BUFFER_SIZE = 1024
MESSAGE = "a"

for i in range(256):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))
    s.send(chr(i).encode())
    total = ""
    l = 0
    while l < 18:
        data = s.recv(BUFFER_SIZE)
        data = data.decode('utf-8','replace')
        l = data[5]
        l += len(data)
        total += data
    if not "Unknown CMD" in total :
        print("byte: %d'0x%02x' -> len(%d) data: %r" % (i, i, len(total), total))

s.close()




def main():
    print('ok')
    pcap_file = open("puzzle.pcap", 'rb')
    pcap = dpkt.pcap.Reader(pcap_file)
    message = collections.OrderedDict()
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if type(eth.data) != dpkt.ip.IP:
            continue
        ip = eth.data
        if type(ip.data) != dpkt.tcp.TCP:
            continue
        tcp = ip.data

        if (tcp.dport==502) and len(tcp.data)>0:
            try:
                modtcp = ModBusTCP(tcp.data)
                if modtcp.fc < 255 and modtcp.proto == 0:
                    if modtcp.ui == 2 and modtcp.fc == 6:
                        try:
                            #print(modtcp.data.decode("ascii"))
                            message[modtcp.ref] = modtcp.data.decode("ascii")
                        except Exception:
                            continue
            except dpkt.dpkt.NeedData:
                continue
    print(sorted(message
                 .items()))
    for key in sorted(message.keys()):
        print("%s" % (message[key]), end='')
        # if (tcp.dport==502) and len(tcp.data)>0:
        #     try:
        #         print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(ts)))
        #         print( 'Src IP:', inet_ntoa(ip.src))
        #         print('Drc IP:', inet_ntoa(ip.dst))
        #         print('Dst Port:', tcp.dport)
        #         modtcp = ModBusTCP(tcp.data)
        #         if modtcp.fc < 255 and modtcp.proto == 0:
        #             print('Unit ID:', modtcp.ui, '\nModbus Function:', modtcp.fc)
        #             print('')
        #     except dpkt.dpkt.NeedData:
        #         continue*/

if __name__== "__main__":
    main()