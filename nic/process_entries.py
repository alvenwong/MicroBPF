#!/usr/bin/env python

class Collector:
    def __init__(self):
        self.data_map = {}
        self.delay_map = {}

    # elements format: SIP, SPORT, DIP, DPORT, SEQ, ACK, TIMESTAMP
    def get_tuple(self, elements):
        key = ''
        start_index = 0
        end_index = 1
        for i in range(start_index, end_index):
            key += str(elements[i])
        return key


    def get_timestamp(self, elements):
        delay_index = 1
        return int(elements[delay_index])


    def get_delay(self, value, timestamp):
        #print(value, timestamp)
        if value > timestamp:
            return value - timestamp;
        else:
            return timestamp - value


    def parse_entries(self, lines):
        for line in lines:
            elements = line.strip('\n').split()
            key = self.get_tuple(elements)
            value = self.get_timestamp(elements)
            timestamp = self.data_map.get(key)
            if timestamp:
                self.delay_map[key] = self.get_delay(value, timestamp)
            else:
                self.data_map[key] = value


    def get_delays(self):
        return self.delay_map
