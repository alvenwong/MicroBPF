#!/usr/bin/env python
import time
import socket


def client_program():
    #host = socket.gethostname()  # as both code is running on same pc
    host = "192.168.0.108"
    port = 5000  # socket server port number
    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    fd = open("test", "rd")
    try:
        while True:
            message = fd.read()
            while message:
                print(message)
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
    client_program()
