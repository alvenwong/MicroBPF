#!/usr/bin/env python

import socket
import select
import errno

response  = b'HTTP/1.0 200 OK\r\nDate: Mon, 1 Jan 1996 01:01:01 GMT\r\n'
response += b'Content-Type: text/plain\r\nContent-Length: 13\r\n\r\n'
response += b'Hello, world!'

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# set SO_REUSEADDR to 1 in this socket
serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host = socket.gethostname()
port = 5000
serversocket.bind((host, port))
serversocket.listen(1)
print("Listening")
# the socket is set to be non-blocking
serversocket.setblocking(0)

epoll = select.epoll()
epoll.register(serversocket.fileno(), select.EPOLLIN)

try:
    connections = {}
    requests = {}
    responses = {}
    while True:
        events = epoll.poll(1)
        for fileno, event in events:
            if fileno == serversocket.fileno():
                connection, address = serversocket.accept()
                print("Connection from: " + str(address))
                connection.setblocking(0)
                cfileno = connection.fileno()
                # Register interest in read (EPOLLIN) events for the new socket.
                epoll.register(cfileno, select.EPOLLIN)
                connections[cfileno] = connection
                requests[cfileno] = b''
                responses[cfileno] = response
            elif event & select.EPOLLIN:
                requests[fileno] = connections[fileno].recv(1024)
                epoll.modify(fileno, select.EPOLLOUT)
                print('-'*40 + '\n' + requests[fileno].decode())
            elif event & select.EPOLLOUT:
                try:
                    byteswritten = connections[fileno].send(responses[fileno])
                    #if len(responses[fileno]) == 0:
                    epoll.modify(fileno, select.EPOLLIN)
                except socket.error, e:
                    if isinstance(e.args, tuple):
                        if e[0] == errno.EPIPE:
                            print("Detected remote disconnect")
                            epoll.unregister(fileno)
                            connections[fileno].close()
                            del connections[fileno]
                            #epoll.modify(fileno, 0)
                            #connections[fileno].shutdown(socket.SHUT_RDWR)
                        else:
                            print("socket error" + e)
            # The HUP (hang-up) event indicates that the client socket has been disconnected.
            elif event & select.EPOLLHUP:
                epoll.unregister(fileno)
                connections[fileno].close()
                del connections[fileno]
except KeyboardInterrupt:
    pass
finally:
    epoll.unregister(serversocket.fileno())
    epoll.close()
    serversocket.close()
