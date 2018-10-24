#!/usr/bin/env python

import socket
import select
import os
import errno
import ConfigParser


config = ConfigParser.RawConfigParser()
cfgFilename = 'example.cfg'


class Server:
    connections = {}
    messages = {}
    filefds = {}

    def __init__(self, host, port, path):
        self.host = host
        self.port = port
        self.path = path
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
        print("Listening")
        # the socket is set to be non-blocking
        self.serversocket.setblocking(0)
        self.epoll.register(self.serversocket.fileno(), select.EPOLLIN)


    def init_accept(self):
        connection, address = self.serversocket.accept()
        print("Connection from: " + str(address))
        connection.setblocking(0)
        cfileno = connection.fileno()
        # Register interest in read (EPOLLIN) events for the new socket.
        self.epoll.register(cfileno, select.EPOLLIN)
        self.connections[cfileno] = connection
        self.filefds[cfileno] = open(self.path+str(address[0])+str(address[1]), "w+")


    def close_connection(self, fileno):
        self.epoll.unregister(fileno)
        self.connections[fileno].close()
        del self.connections[fileno]
        self.filefds[fileno].close()



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
                            print(message)
                            self.filefds[fileno].write(message)
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
                        byteswritten = connections[fileno].send(responses[fileno])
                        self.epoll.modify(fileno, select.EPOLLIN)
                    except socket.error, e:
                        if isinstance(e.args, tuple):
                            if e[0] == errno.EPIPE:
                                print("Detected remote disconnect")
                        else:
                             print("socket error" + e)
                        self.close_connection(fileno)
                # The HUP (hang-up) event indicates that the client socket has been disconnected.
                elif event & select.EPOLLHUP:
                    self.close_connection(fileno)


    def shutdown(self):
        self.epoll.unregister(self.serversocket.fileno())
        self.epoll.close()
        self.serversocket.close()


    def run(self):
        self.valid_path()
        self.start()
        try:
            self.process()
        except KeyboardInterrupt:
            exit()
        finally:
            self.shutdown()


def get_parameters():
    config.read(cfgFilename)
    host = config.get("Socket", "IP")
    port = config.get("Socket", "port")
    path = config.get("File", "path")
    return host, int(port), path


if __name__ == "__main__":
    host, port, path = get_parameters()
    server = Server(host, port, path)
    server.run()
