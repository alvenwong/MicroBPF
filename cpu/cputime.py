#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# cpudist   Summarize on- and off-CPU time per task as a histogram.
#
# USAGE: cpudist [-h] [-O] [-T] [-m] [-P] [-L] [-p PID] [interval] [count]
#
# This measures the time a task spends on or off the CPU, and shows this time
# as a histogram, optionally per-process.
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
from proc_cputime import ProcStat
from proc_pid_cputime import ProcPidStat, check_pid

examples = """examples:
    cpudist              # summarize on-CPU time as a histogram
    cpudist 1 10         # print 1 second summaries, 10 times
    cpudist -mT 1        # 1s summaries, milliseconds, and timestamps
    cpudist -P           # show each PID separately
    cpudist -p 185       # trace PID 185 only
"""
parser = argparse.ArgumentParser(
    description="Summarize on-CPU time per task as a histogram.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="millisecond histogram")
parser.add_argument("-P", "--pids", action="store_true",
    help="print a histogram per process ID")
parser.add_argument("-L", "--tids", action="store_true",
    help="print a histogram per thread ID")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.count)
debug = 0

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>


struct cputime_t {
    u64 task_report;
    u64 task_running;
    u64 task_interruptible;
    u64 task_uninterruptible;
    u64 task_utime;
    u64 task_stime;
};


BPF_HASH(start, u32, u64);
BPF_HASH(cputime, u32, struct cputime_t);


static inline void store_start(u32 tgid, u32 pid, u64 ts)
{
    if (FILTER)
        return;

    start.update(&pid, &ts);
}


static inline u64 get_delta(u32 tgid, u32 pid, u64 ts)
{
    if (FILTER)
        return 0;

    u64 *tsp = start.lookup(&pid);
    if (tsp == 0)
        return 0;

    if (ts < *tsp) {
        // Probably a clock issue where the recorded on-CPU event had a
        // timestamp later than the recorded off-CPU event, or vice versa.
        return 0;
    }
    u64 delta = ts - *tsp;
    FACTOR
    return delta;
}


static inline int update_cputime(u32 tgid, u32 pid, struct cputime_t *cur)
{
    if (FILTER)
        return 0;

    struct cputime_t *tsp, zero = {};
    if ((tsp = cputime.lookup_or_init(&pid, &zero)) == NULL)
        return 0;
    
    tsp->task_report += cur->task_report;
    tsp->task_running += cur->task_running;
    tsp->task_interruptible += cur->task_interruptible;
    tsp->task_uninterruptible += cur->task_uninterruptible;
    return 0;
}


int sched_switch(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32, pid = pid_tgid;
    u64 delta = 0;

    u32 prev_pid = prev->pid;
    u32 prev_tgid = prev->tgid;
    delta = get_delta(prev_tgid, prev_pid, ts);
    struct cputime_t data = {};
    if (delta > 0)
    {
        data.task_report = delta;
        if (prev->state == TASK_RUNNING) 
        {
            data.task_running = delta;
        } else if ((prev->state ==  TASK_INTERRUPTIBLE) != 0) {
            data.task_interruptible = delta;
        } else if (prev->state == TASK_UNINTERRUPTIBLE) {
            data.task_uninterruptible = delta;
        }
        data.task_utime = prev->utime;
        data.task_stime = prev->stime;
        update_cputime(prev_tgid, prev_pid, &data);
    }

    store_start(tgid, pid, ts);

    return 0;
}
"""


if args.pid:
    bpf_text = bpf_text.replace('FILTER', 'tgid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '0')
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000000;')
    label = "msecs"
else:
    bpf_text = bpf_text.replace('FACTOR', 'delta /= 1000;')
    label = "usecs"
if args.pids or args.tids:
    section = "pid"
    pid = "tgid"
    if args.tids:
        pid = "pid"
        section = "tid"
else:
    section = ""
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

b = BPF(text=bpf_text)
b.attach_kprobe(event="finish_task_switch", fn_name="sched_switch")

print("Tracing %s-CPU time... Hit Ctrl-C to end.")

exiting = 0 if args.interval else 1
cputime = b.get_table("cputime")

cputime_stat = ProcStat()

while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    busy_BPF = 0 
    idle_BPF = 0
    run_BPF = 0
    interruptible_BPF = 0
    uninterruptible_BPF = 0
    utime_BPF = 0
    stime_BPF = 0

    pids = []
    for pid, time in cputime.items():
        if (pid.value != 0):
            busy_BPF += time.task_report
            run_BPF += time.task_running
            interruptible_BPF += time.task_interruptible
            uninterruptible_BPF += time.task_uninterruptible
            utime_BPF = time.task_utime
            stime_BPF = time.task_stime
        else:
            idle_BPF = time.task_report;

        pids.append(pid.value)
        
    pid_total = 0
    pid_usr = 0
    pid_sys = 0

    print(len(pids))
    for pid in pids:
        if check_pid(pid):
            pid_cputime_stat = ProcPidStat(pid)
            pid_cputime_stat.update_pid_stat()
            #print(pid, pid_cputime_stat.get_usr_value(), pid_cputime_stat.get_sys_value())
            pid_total += pid_cputime_stat.get_cputime()
            pid_usr += pid_cputime_stat.get_usrtime()
            pid_sys += pid_cputime_stat.get_systime()

    cputime_stat.update_cpu_stat()

    print("Busy time BPF: ", busy_BPF)
    print("Idle time BPF: ", idle_BPF)
    print("Running time BPF: ", run_BPF)
    print("Interruptible time BPF: ", interruptible_BPF)
    print("Uninterruptible time BPF: ", uninterruptible_BPF)
    print("utime BPF: ", utime_BPF/1000)
    print("stime BPF: ", stime_BPF/1000) 
    print()

    print("total CPU time: ", cputime_stat.get_total_cputime()) 
    print("IDLE CPU time:", cputime_stat.get_idle_cputime())
    print("IRQ CPU time:", cputime_stat.get_irq_cputime())
    print("USR CPU time:", cputime_stat.get_usr_cputime())
    print("SYS CPU time:", cputime_stat.get_sys_cputime())
    print()

    print("PID total cputime: ", pid_total) 
    print("PID usr cputime: ", pid_usr) 
    print("PID sys cputime: ", pid_sys) 

    print("*"*20)
    cputime.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()
