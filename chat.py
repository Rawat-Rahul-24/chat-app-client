#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import socket
import threading
from keyGeneration import *


class Peer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connections = []
        self.pub_key = None

    def start(self):
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        print(f"Listening for connections on {self.host}:{self.port}")
        threading.Thread(target=self.accept_connections).start()

    def accept_connections(self):
        while True:
            client_socket, client_address = self.sock.accept()
            print(f"Connection established with {client_address}")
            self.connections.append(client_socket)
            threading.Thread(target=self.receive_message, args=(client_socket,)).start()
            self.pub_key = generate_ecc_keys()

    def connect_to_peer(self, peer_host, peer_port):
        peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            peer_socket.connect((peer_host, peer_port))
            print(f"Connected to peer at {peer_host}:{peer_port}")
            self.connections.append(peer_socket)
            threading.Thread(target=self.receive_message, args=(peer_socket,)).start()
        except ConnectionRefusedError:
            print(f"Connection to {peer_host}:{peer_port} failed")

    def receive_message(self, connection):
        while True:
            try:
                message = connection.recv(1024).decode()
                if message:
                    print(message)
            except ConnectionResetError:
                self.connections.remove(connection)
                print("Connection closed by peer")
                break

    def send_message(self, message):
        for connection in self.connections:
            try:
                connection.sendall(message.encode())
            except ConnectionResetError:
                self.connections.remove(connection)
                print("Connection closed by peer")


if __name__ == "__main__":
    # Example usage
    peer = Peer("localhost", 5000)
    peer.start()

    peer_host = input("Enter peer host: ")
    peer_port = int(input("Enter peer port: "))
    peer.connect_to_peer(peer_host, peer_port)

    while True:
        message = input("Enter message: ")
        peer.send_message(encrypt(message))

# In[ ]:
