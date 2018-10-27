#!/usr/bin/env python
import time
import socket
import ConfigParser


class Client:
    def __init__(self, cfg):
        self.host, self.port, self.paths = self.get_parameters(cfg)
        self.fds = {}
        self.open_files()
        

    def __del__(self):
        print("Exit")
        self.close_files()


    def get_parameters(self, cfg):
        config = ConfigParser.RawConfigParser()
        config.read(cfg)
        host = config.get("Socket", "IP")
        port = config.get("Socket", "port")
        paths = []
        path_out = config.get("File", "path_out")
        paths.append(path_out)
        path_in = config.get("File", "path_in")
        paths.append(path_in)
        path_ack = config.get("File", "path_ack")
        paths.append(path_ack)
        return host, int(port), paths


    def open_file(self, path):
        fd = open(path, 'a+')
        self.fds[path] = fd
    
    
    def open_files(self):
        for path in self.paths:
            self.open_file(path)
    
    
    def close_file(self, fd):
        fd.close()
    

    def close_files(self):
        for fd in self.fds.values():
            self.close_file(fd)


    def client_program(self):
        client_socket = socket.socket()  # instantiate
        client_socket.connect((self.host, self.port))  # connect to the server
        
        try:
            while True:
                for fd in self.fds.values():
                    message = fd.read()
                    while message:
                        client_socket.send(message.encode())  # send message
                        message = fd.read()
                    fd.seek(0, 2)
            time.sleep(5)
        except KeyboardInterrupt:
            pass
        finally:
            self.close_files()
            client_socket.close()  # close the connection


if __name__ == '__main__':
    cfg = 'client.cfg'
    client = Client(cfg)
    client.client_program()
