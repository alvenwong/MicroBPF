#!/usr/bin/env python

from process_entries import Collector
from read_files import ReadFiles

path = "trace/"
files = ReadFiles(path)
lines = files.get_new_data()
collector = Collector()
collector.parse_entries(lines)
print(collector.get_delays())
