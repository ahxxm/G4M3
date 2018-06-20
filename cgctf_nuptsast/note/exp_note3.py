#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

context.log_level = 'debug'

fn = './note3'

if len(sys.argv) == 1:
    io = process(fn)
    libn = '/lib/x86_64-linux-gnu/libc.so.6'
else:
    io = remote('45.76.173.177', 6666)
    libn = './libc-2.24.so'

libc = ELF(libn)
elf = ELF(fn)

# 攻击思路设想：将fastbin分配到bss上，控制notes整体的指针，实现任意地址读写

