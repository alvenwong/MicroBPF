#!/usr/bin/env python

__all__ = ["Time"]

import ctypes, os
import time
import subprocess

"""
#define CLOCK_REALTIME                  0
#define CLOCK_MONOTONIC                 1
#define CLOCK_PROCESS_CPUTIME_ID        2
#define CLOCK_THREAD_CPUTIME_ID         3
#define CLOCK_MONOTONIC_RAW             4
#define CLOCK_REALTIME_COARSE           5
#define CLOCK_MONOTONIC_COARSE          6
#define CLOCK_BOOTTIME                  7
#define CLOCK_REALTIME_ALARM            8
#define CLOCK_BOOTTIME_ALARM            9
#define CLOCK_SGI_CYCLE                10      
#define CLOCK_TAI                      11 
"""


class Time:
    class timespec(ctypes.Structure):
        _fields_ = [
            ('tv_sec', ctypes.c_long),
            ('tv_nsec', ctypes.c_long)
        ]

    librt = ctypes.CDLL('librt.so.1', use_errno=True)
    clock_gettime = librt.clock_gettime
    CLOCK_REALTIME = 0
    CLOCK_MONOTONIC = 1
    
    def __init__(self):
        self.clock_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(self.timespec)]
        self.starttime = self.get_start_time()
    
    def get_realtime(self):
        t = self.timespec()
        if self.clock_gettime(self.CLOCK_REALTIME, ctypes.pointer(t)) != 0:
            errno_ = ctypes.get_errno()
            raise OSError(errno_, os.strerror(errno_))
        return t.tv_sec + t.tv_nsec * 1e-9


    def get_monotonic_time(self):
        t = self.timespec()
        if self.clock_gettime(self.CLOCK_MONOTONIC, ctypes.pointer(t)) != 0:
            errno_ = ctypes.get_errno()
            raise OSError(errno_, os.strerror(errno_))
        return t.tv_sec + t.tv_nsec * 1e-9


    def get_start_time(self):
        return self.get_realtime() - self.get_monotonic_time() 


    def get_abs_time(self, monotonic):
        return self.starttime + monotonic


    def syn_time(self):
        cmd = "ntpdate -qu 1.ro.pool.ntp.org"
        subprocess.Popen(cmd, shell =True, stdout=subprocess.PIPE)
        self.starttime = self.get_start_time()
