#!/usr/bin/env python

from process_entries import Collector
from read_files import ReadFiles
import sys

path = "trace/"
files = ReadFiles(path)
lines = files.get_new_data()
collector = Collector()
collector.parse_entries(lines)
delay, rtt = collector.get_maps()

sys.stdout = open("delay", 'wb')
for ips, items in delay.items():
    print ips
    print '-'*20
    for value in items.values():
        print "%f" % value

sys.stdout = open("rtt", 'wb')
for ips, items in rtt.items():
    print ips
    print '-'*20
    for value in items.values():
        print "%f" % value
