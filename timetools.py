#!/usr/bin/env python


from __future__ import print_function
import time
import subprocess


class Time:
    def __init__(self):
        self.realtime = time.CLOCK_REALTIME
        self.monotonic = time.CLOCK_MONOTONIC
        self.boottime = self.get_boottime()

    def get_realtime(self):
        return time.clock_gettime(self.realtime)

    def get_monotonic(self):
        return time.clock_gettime(self.monotonic)

    def get_boottime(self):
        return self.get_realtime() - self.get_monotonic()

    def get_abs_time(self, monotonic):
        return self.boottime + self.monotonic

    def syn_time(self):
        cmd = "ntpdate -qu 1.ro.pool.ntp.org"
        subprocess.Popen(cmd, shell=True)
        self.boottime = self.get_boottime()
