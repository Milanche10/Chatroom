import socket
import threading
import json

class Server:
    def __init__(self, host, port):
        self.clients = {}  # sock -> username
        self.host = host
        self.port = port

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        print(f"Server running on {self.host}:{self.port}")

        while True:
            sc, addr = sock.accept()
            print(f"New connection from {addr}")
            threading.Thread(target=self.handle_client, args=(sc,), daemon=True).start()

    def send_json(self, client, data):
        try:
            client.sendall((json.dumps(data) + "\n").encode("utf-8"))
        except:
            client.close()

    def broadcast(self, data, exclude=None):
        for c in list(self.clients.keys()):
            if c != exclude:
                self.send_json(c, data)

    def find_client_by_name(self, username):
        for c, u in self.clients.items():
            if u == username:
                return c
        return None

    def handle_client(self, sc):
        buffer = ""
        username = None
        while True:
            try:
                data = sc.recv(1024).decode("utf-8")
                if not data:
                    break
                buffer += data
                while "\n" in buffer:
                    msg, buffer = buffer.split("\n", 1)
                    if msg.strip():
                        data_json = json.loads(msg)
                        msg_type = data_json.get("type")

                        if msg_type == "join":
                            username = data_json["user"]
                            self.clients[sc] = username
                            self.broadcast({"type": "join", "user": username}, exclude=None)

                        elif msg_type == "chat":
                            self.broadcast(data_json)

                        elif msg_type == "call_request":
                            target = self.find_client_by_name(data_json["to"])
                            if target:
                                self.send_json(target, data_json)

                        elif msg_type == "call_response":
                            target = self.find_client_by_name(data_json["to"])
                            if target:
                                self.send_json(target, data_json)

                        elif msg_type == "end_call":
                            target = self.find_client_by_name(data_json["to"])
                            if target:
                                self.send_json(target, data_json)

            except Exception as e:
                print("Error:", e)
                break

        if username:
            print(f"{username} disconnected")
            del self.clients[sc]
        sc.close()

if __name__ == "__main__":
    server = Server("0.0.0.0", 1060)
    server.start()
