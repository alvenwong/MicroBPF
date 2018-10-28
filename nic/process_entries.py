#!/usr/bin/env python

TCPOUT = '1'
TCPIN = '2'
TCPACK = '3'


class Collector:
    def __init__(self):
        self.data_map = {}
        self.delay_map = {}
        self.rtt_map = {}


    def get_ips(self, elements):
        sip = ''
        dip = ''

        if elements[0] == TCPOUT:
            sip = elements[3].split(':')[0]
            dip = elements[5].split(':')[0]
        elif elements[0] == TCPIN:
            sip = elements[1].split(':')[0]
            dip = elements[3].split(':')[0]
        elif elements[0] == TCPACK:
            sip = elements[1].split(':')[0]
            dip = elements[3].split(':')[0]

        return sip


    def get_tuple_index(self, elements):
        # tcp out elements
        if elements[0] == TCPOUT:
            return [6, 7]
        # tcp in elements
        elif elements[0] == TCPIN: 
            return [4, 5]
        elif elements[0] == TCPACK:
            return [4, 5]
        else:
            return []


    def get_tuple(self, elements):
        key = ''
        index = self.get_tuple_index(elements)
        if len(index) == 0:
            return ''

        for i in index:
            key += elements[i] + ' '
        return key


    def get_timestamp_index(self, elements):
        if elements[0] == TCPOUT:
            return 8
        elif elements[0] == TCPIN:
            return 6
        elif elements[0] == TCPACK:
            return 6
        else:
            return -1
        

    def get_timestamp(self, elements):
        index = self.get_timestamp_index(elements)
        if index == -1:
            return -1
        else:
            return (float(elements[index]))


    def get_delay(self, value, timestamp):
        if value > timestamp:
            return value - timestamp;
        else:
            return timestamp - value


    def check_line(self, elements):
        if (elements[0] == TCPOUT and len(elements) == 13) \
            or (elements[0] == TCPIN and len(elements) == 11) \
            or (elements[0] == TCPACK and len(elements) == 10): 
            return True

        return False

    def parse_entries(self, lines):
        for line in lines:
            elements = line.strip('\n').split()
            if not self.check_line(elements):
                continue
            lable = elements[0]
            ips = self.get_ips(elements)
            key = self.get_tuple(elements)
            value = self.get_timestamp(elements)

            if lable == TCPACK:
                if ips not in self.rtt_map:
                    self.rtt_map[ips] = {}
                self.rtt_map[ips][key] = value
                continue

            if key not in self.data_map:
                self.data_map[key] = value
            else:
                if ips not in self.delay_map:
                    self.delay_map[ips] = {}
                self.delay_map[ips][key] = self.get_delay(value, self.data_map[key]) 
                del self.data_map[key]

    def get_maps(self):
        return self.delay_map, self.rtt_map
