#!/usr/bin/env python

import subprocess
from os import kill
from signal import SIGKILL

proc = subprocess.Popen("ps aux | grep py", stdout=subprocess.PIPE, shell=True)
(out, err) = proc.communicate()

print out
lines = out.split('\n')
pid = int(lines[0].split()[1])

kill(pid, SIGKILL)
