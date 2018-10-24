#!/usr/bin/env python
import time
import socket
import ConfigParser


def get_parameters(cfg):
    config = ConfigParser.RawConfigParser()
    config.read(cfg)
    host = config.get("Socket", "IP")
    port = config.get("Socket", "port")
    path = config.get("File", "path")
    return host, int(port), path


def client_program(host, port, path):
    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    fd = open(path, "rd")
    try:
        while True:
            message = fd.read()
            while message:
                client_socket.send(message.encode())  # send message
                message = fd.read()
            fd.seek(0, 2)
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        fd.close()
        client_socket.close()  # close the connection


if __name__ == '__main__':
    cfgFilename = 'example.cfg'
    host, port, path = get_parameters(cfgFilename) 
    client_program(host, port, path)
