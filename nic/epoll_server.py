#!/usr/bin/env python

import socket
import select
import os
import errno
import ConfigParser


def get_parameters():
    config = ConfigParser.RawConfigParser()
    cfgFilename = 'server.cfg'
    config.read(cfgFilename)
    host = config.get("Socket", "IP")
    port = config.get("Socket", "port")
    path = config.get("File", "path")
    msize = config.get("File", "max_size")
    return host, int(port), path


class Server:
    connections = {}
    messages = {}
    filefds = {}
    addresses = {}
    findex = {}
    filenames = {}

    def __init__(self, host, port, path, msize=10*1024*1024):
        self.host = host
        self.port = port
        self.path = path
        self.MAX_FILE_SIZE = msize
        self.serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.epoll = select.epoll()


    def valid_path(self):
        if not os.path.exists(self.path):
            os.makedirs(self.path)


    def start(self):
        # set SO_REUSEADDR to 1 in this socket
        self.serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.serversocket.bind((self.host, self.port))
        self.serversocket.listen(1)
        # the socket is set to be non-blocking
        self.serversocket.setblocking(0)
        self.epoll.register(self.serversocket.fileno(), select.EPOLLIN)


    def update_file(self, fileno):
        findex = self.findex[fileno]
        if findex > 1:
            try:
                self.filefds[fileno].close()
            except IOError, e:
                print(e)

        address = self.addresses[fileno]
        filename = self.path + str(address[0]) + '_' + str(address[1]) + '_' + str(findex)
        self.filenames[fileno] = filename
        self.filefds[fileno] = open(filename, 'a+')
        self.findex[fileno] += 1


    def init_accept(self):
        connection, address = self.serversocket.accept()
        print("Connection from: " + str(address))
        connection.setblocking(0)
        cfileno = connection.fileno()
        # Register interest in read (EPOLLIN) events for the new socket.
        self.epoll.register(cfileno, select.EPOLLIN)
        self.connections[cfileno] = connection
        self.addresses[cfileno] = address
        self.findex[cfileno] = 0
        self.update_file(cfileno)


    def close_connection(self, fileno):
        self.epoll.unregister(fileno)
        self.connections[fileno].close()
        del self.connections[fileno]
        self.filefds[fileno].close()


    def close_connections(self):
        for fd in self.filefds.keys():
            self.close_connection(fd)    
    
    def get_file_size(self, fileno):
       return os.path.getsize(self.filenames[fileno])


    def process(self):
        while True:
            events = self.epoll.poll(1)
            for fileno, event in events:
                if fileno == self.serversocket.fileno():
                    self.init_accept()
                elif event & select.EPOLLIN:
                    try:
                        self.messages[fileno] = self.connections[fileno].recv(1024)
                        message = self.messages[fileno].decode()
                        if len(message) > 0:
                            self.filefds[fileno].write(message)
                            if self.get_file_size(fileno) > self.MAX_FILE_SIZE:
                                self.update_file(fileno)
                        self.epoll.modify(fileno, select.EPOLLIN)
                    except socket.error, e:
                        if isinstance(e.args, tuple):
                            if e[0] == errno.EPIPE:
                                print("Detected remote disconnect")
                            else:
                                print("socket error")
                        else:
                            print("socket error" + e)
                        self.close_connection(fileno)
                elif event & select.EPOLLOUT:
                    try:
                        byteswritten = connections[fileno].send("test".encode())
                        self.epoll.modify(fileno, select.EPOLLIN)
                    except socket.error, e:
                        if isinstance(e.args, tuple):
                            if e[0] == errno.EPIPE:
                                print("Detected remote disconnect")
                        else:
                             print("socket error" + e)
                        self.close_connection(fileno)
                # The HUP (hang-up) event indicates that the client socket has been disconnected.
                elif event & (select.EPOLLHUP or select.EPOLLERR):
                    print("connection closed")
                    self.close_connection(fileno)


    def shutdown(self):
        self.close_connections()
        self.epoll.unregister(self.serversocket.fileno())
        self.epoll.close()
        self.serversocket.close()


    def run(self):
        self.valid_path()
        self.start()
        try:
            self.process()
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()


if __name__ == "__main__":
    host, port, path = get_parameters()
    server = Server(host, port, path)
    server.run()
