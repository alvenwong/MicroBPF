#!/usr/bin/env python

import socket
import select
import errno
import ConfigParser


config = ConfigParser.RawConfigParser()
cfgFilename = 'example.cfg'

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.epoll = select.epoll()

    def start(self):
        # set SO_REUSEADDR to 1 in this socket
        self.serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.serversocket.bind((self.host, self.port))
        self.serversocket.listen(1)
        print("Listening")
        # the socket is set to be non-blocking
        self.serversocket.setblocking(0)
        self.epoll.register(self.serversocket.fileno(), select.EPOLLIN)

    def process(self):
        connections = {}
        requests = {}
        responses = {}
        while True:
            events = self.epoll.poll(1)
            for fileno, event in events:
                if fileno == self.serversocket.fileno():
                    connection, address = self.serversocket.accept()
                    print("Connection from: " + str(address))
                    connection.setblocking(0)
                    cfileno = connection.fileno()
                    # Register interest in read (EPOLLIN) events for the new socket.
                    self.epoll.register(cfileno, select.EPOLLIN)
                    connections[cfileno] = connection
                elif event & select.EPOLLIN:
                    requests[fileno] = connections[fileno].recv(4096)
                    print('-'*40 + '\n' + requests[fileno].decode())
                    self.epoll.modify(fileno, select.EPOLLIN)
                    responses[fileno] = ''
                elif event & select.EPOLLOUT:
                    try:
                        byteswritten = connections[fileno].send(responses[fileno])
                        self.epoll.modify(fileno, select.EPOLLIN)
                    except socket.error, e:
                        if isinstance(e.args, tuple):
                            if e[0] == errno.EPIPE:
                                print("Detected remote disconnect")
                                self.epoll.unregister(fileno)
                                connections[fileno].close()
                                del connections[fileno]
                                #epoll.modify(fileno, 0)
                                #connections[fileno].shutdown(socket.SHUT_RDWR)
                            else:
                                print("socket error" + e)
                # The HUP (hang-up) event indicates that the client socket has been disconnected.
                elif event & select.EPOLLHUP:
                    self.epoll.unregister(fileno)
                    connections[fileno].close()
                    del connections[fileno]


    def shutdown(self):
        self.epoll.unregister(self.serversocket.fileno())
        self.epoll.close()
        self.serversocket.close()


    def run(self):
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
    return host, int(port)


if __name__ == "__main__":
    host, port = get_parameters()
    server = Server(host, port)
    server.run()
