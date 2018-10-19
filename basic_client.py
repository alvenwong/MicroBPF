#!/usr/bin/env python
import time
import socket


def client_program():
    #host = socket.gethostname()  # as both code is running on same pc
    host = "127.0.0.1"
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server
    fd = open("test", "rd")
    try:
        while True:
            message = fd.read(1024)
            while message:
                print("Sending...")
                client_socket.send(message.encode())  # send message
                #data = client_socket.recv(1024).decode()  # receive response
                #print('Received from server: ' + data)  # show in terminal
                message = fd.read(1024)
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        fd.close()
        client_socket.close()  # close the connection


if __name__ == '__main__':
    client_program()
