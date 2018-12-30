#!/usr/bin/env python

import os

__all__ = ["ProcPidStat", "check_pid"]

class Multiton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        key  = (cls, args)
        if key not in cls._instances:
            cls._instances[key] = super(Multiton, cls).__call__(*args, **kwargs)
        return cls._instances[key]
        
    
class ProcPidStat(object):
    __metaclass__ = Multiton

    def __init__(self, pid):
        self.pid = pid
        self.path = "/proc/%d/stat" % pid
        self.prev = []
        self.cur = self.get_pid_stat()
        self.usr_index = 13
        self.system_index = 14
        self.comm = self.get_pid_comm()


    def get_pid_stat(self):
        return open(self.path, "r").read().split()
    
     
    def update_pid_stat(self):
        self.prev = self.cur
        self.cur = self.get_pid_stat()


    def get_pid_comm(self):
        return self.cur[1]
    

    def get_prev_value(self, index):
        return int(self.prev[index])


    def get_cur_value(self, index):
        return int(self.cur[index])


    def get_value(self, index):
        return self.get_cur_value(index), self.get_prev_value(index)


    def get_usr_value(self):
        return self.get_value(self.usr_index)


    def get_sys_value(self):
        return self.get_value(self.system_index)


    def get_interval(self, index):
        return self.get_cur_value(index) - self.get_prev_value(index)


    def get_usrtime(self):
        return self.get_interval(self.usr_index)


    def get_systime(self):
        return self.get_interval(self.system_index)


    def get_cputime(self):
        return self.get_usrtime() + self.get_systime()



def check_pid(pid):
    path = "/proc/%d/stat" % pid
    if os.path.exists(path):
        return True
    
    return False
