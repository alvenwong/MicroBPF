#!/usr/bin/env python

__all__ = ["monotonic_time"]

import ctypes, os
#import psutil
import time

CLOCK_MONOTONIC_RAW = 4 # see <linux/time.h>
CLOCK_REALTIME = 1

class timespec(ctypes.Structure):
    _fields_ = [
        ('tv_sec', ctypes.c_long),
        ('tv_nsec', ctypes.c_long)
    ]

librt = ctypes.CDLL('librt.so.1', use_errno=True)
clock_gettime = librt.clock_gettime
clock_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(timespec)]

def monotonic_time():
    t = timespec()
    if clock_gettime(CLOCK_MONOTONIC_RAW , ctypes.pointer(t)) != 0:
    #if clock_gettime(time.CLOCK_REALTIME, ctypes.pointer(t)) != 0:
        errno_ = ctypes.get_errno()
        raise OSError(errno_, os.strerror(errno_))
    return t.tv_sec + t.tv_nsec * 1e-9


def boot_time():
    return timetime() - monotonic_time() 

def timetime():
    return time.time()

if __name__ == "__main__":
    print(boot_time())
    print(monotonic_time(), time.monotonic())
