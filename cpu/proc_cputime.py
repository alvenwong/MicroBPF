#!/usr/bin/env python

class ProcStat:
    def __init__(self):
        self.min_index = 1
        self.max_index = 8
        self.usr_index = 1
        self.nice_index = 2
        self.sys_index = 3
        self.idle_index = 4
        self.iowait_index = 5
        self.irq_index = 6
        self.softirq_index = 7
        self.steal_index = 8

        self.path = "/proc/stat"
        self.prev = []
        self.cur = self.get_cpu_stat()


    def get_cpu_stat(self):
        return open(self.path, 'r').readline().split()


    def update_cpu_stat(self):
        self.prev = self.cur
        self.cur = self.get_cpu_stat()


    def get_interval(self, index):
        return int(self.cur[index]) - int(self.prev[index])


    def get_total_cputime(self):
        total = 0
        for index in range(self.min_index, self.max_index+1):
            total += self.get_interval(index)

        return total


    def get_usr_cputime(self):
        return self.get_interval(self.usr_index)


    def get_sys_cputime(self):
        return self.get_interval(self.sys_index)
    

    def get_idle_cputime(self):
        # idle time + iowait time
        return self.get_interval(self.idle_index) + self.get_interval(self.iowait_index)

    
    def get_irq_cputime(self):
        # irq time + softirq time
        return self.get_interval(self.irq_index) + self.get_interval(self.softirq_index)


