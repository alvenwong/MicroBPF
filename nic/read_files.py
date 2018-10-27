#!/usr/bin/env python

from time import sleep
import os


class ReadFiles:
    def __init__(self, path):
        self.path = path
        self.files = []
        self.new_files = []
        self.fds = {}
        self.get_files()
        self.open_files()

    def __del__(self):
        self.close_files()

    def get_files(self):
        for filename in os.listdir(self.path):
            if os.path.isfile(os.path.join(self.path, filename)):
                self.files.append(filename)

    def get_filenames(self):
        return self.files
        

    def open_file(self, filename):
        filepath = os.path.join(self.path, filename)
        try:
            fd = open(filepath, "rb")
            print(filepath)
            return fd
        except (OSError, IOError) as e:
            print("%s open error!" % (filepath))

    def open_files(self):
        for filename in self.files:
            # need to handle file open error
            self.fds[filename] = self.open_file(filename)

    def close_file(self, fd):
        fd.close()
        
    def close_files(self):
        for fd in self.fds.values():
            self.close_file(fd)

    def get_new_files(self):
        self.new_files = []
        for filename in os.listdir(self.path):
            if os.path.isfile(os.path.join(self.path, filename)) and filename not in self.files:
                self.new_files.append(filename)

        self.files += self.new_files

    def open_new_files(self):
        for filename in self.new_files:
            self.fds[filename] = self.open_file(filename)


    def get_new_data_from_file(self, fd):
        lines = fd.readlines()
        fd.seek(0, 2)
        return lines

    def get_new_data(self):
        lines = []
        for fd in self.fds.values():
            lines += self.get_new_data_from_file(fd)
        return lines

