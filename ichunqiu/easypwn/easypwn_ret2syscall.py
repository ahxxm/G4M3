#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import sys
import struct
from zio import *
from termcolor import *

class Config:
    exe = './easypwn'

class Local(Config):
    host = '127.0.0.1'
    port = 4444

    def __init__(self):
        # self.io = zio(Config.exe, print_read=COLORED(RAW, 'red'), print_write=(RAW, 'green'))
        self.io = zio(Config.exe)


class Remote(Config):
    host = '106.75.66.195'
    port = 20000

    def __init__(self):
        # self.io = zio(Remote.host, Remote.port, print_read=COLORED(RAW, 'red'), print_write=(RAW, 'green'))
        self.io = zio((Remote.host, Remote.port))


class Exploit:
    io = None

    @staticmethod
    def exp():
        e = Exploit
        e.io = Local().io if len(sys.argv) == 1 else Remote().io
        e.io.read_until('you?\n')
        e.io.writeline('aaa')
        e.io.read_until('')
        e.io.close('name?\n')
        e.io.writeline('bbb')
        e.io.read_until('again!\n')
        e.io.close()

if __name__ == '__main__':
    Exploit.exp()
