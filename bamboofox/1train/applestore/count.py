#!/usr/bin/env python
# -*- coding: utf-8 -*-

n = 7174
for i1 in xrange(n // 199 + 1):
    for i2 in xrange(n // 299 + 1):
        for i3 in xrange(n // 499 + 1):
            for i4 in xrange(n // 399 + 1):
                m = i1 * 199 + i2 * 299 + i3 * 499 + i4 * 399
                if m == n:
                    print i1, i2, i3, i4
