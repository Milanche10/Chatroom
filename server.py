import threading
import socket
import argparse
import os



class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.connection = []
        self.host = host
        self.port = port

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(1)
        print("Listening on %s:%d" % (self.host, self.port))
        print("Listening at", sock.getsockname())

        while True:
            # Accepting new connection
            sc, sockname = sock.accept()
            print(f"Accepted connection from {sc.getpeername()} to {sc.getsockname()}")

            #Create a new thread
            server_socket = ServerSocket(sc, sockname, self)

            #Start a new thread
            server_socket.start()

            #Add thread to active connection
            self.connection.append(server_socket)
            print(f"Ready to receive message from {sc.getpeername()}")


    def broadcast(self, message, source):
        for connection in self.connection:
            # send to all connected clients except the source client
            if connection.sockname != source:
                connection.send(message)

    def remove_connection(self, connection):
        self.connection.remove(connection)

class ServerSocket(threading.Thread):
    def __init__(self, sc, sockname, server):
        super().__init__()
        self.sc = sc
        self.sockname = sockname
        self.server = server

    def run(self):
        while True:
            message = self.sc.recv(1024).decode('ascii')

            if message:
                print(f"{self.sockname} says: {message}")
                self.server.broadcast(message, self.sockname)
            else:
                print(f"{self.sockname} closed")
                self.sc.close()
                server.remove_connection(self)
                return

    def send(self, message):
        self.sc.sendall(message.encode('ascii'))

def handle_exit(server):
    while True:
        ipt = input("")
        if ipt == "q":
            print("Closing all connections")
            for connection in server.connection:
                connection.sc.close()
            print("Shutting down the server")
            os._exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chatroom server")
    parser.add_argument("-host", default="127.0.0.1", help="Interface the server is listening on")
    parser.add_argument("-p", metavar='PORT', type=int, default=1060, help='TCP port (default: 1060)')

    args = parser.parse_args()

    #create server and start thread
    server = Server(args.host, args.p)
    server.start()

    exit_thread = threading.Thread(target=handle_exit, args=(server,))
    exit_thread.start()


