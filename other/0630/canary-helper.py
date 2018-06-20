#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys

ebp = sys.argv[1]
canary_offset = sys.argv[2]

canary = int(ebp, 16) - int(canary_offset)

print 'x/wx {}'.format(hex(canary))
