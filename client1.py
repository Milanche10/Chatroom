import socket
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
import argparse
import json

class Client:
    def __init__(self, server_ip, port, username):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((server_ip, port))
        self.username = username

        # Šaljemo serveru username odmah
        self.send_json({"type": "join", "user": self.username})

        self.root = tk.Tk()
        self.root.title(f"Chat - {self.username}")

        self.text_area = tk.Text(self.root, state="disabled", height=20, width=50)
        self.text_area.pack()

        self.entry = tk.Entry(self.root, width=40)
        self.entry.pack(side="left", padx=5, pady=5)
        self.entry.bind("<Return>", self.send_message)

        self.send_btn = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_btn.pack(side="left")

        self.call_btn = tk.Button(self.root, text="Call", command=self.make_call)
        self.call_btn.pack(side="left")

        # Thread za slušanje servera
        threading.Thread(target=self.listen_server, daemon=True).start()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    def send_json(self, data):
        self.sock.sendall((json.dumps(data) + "\n").encode("utf-8"))

    def send_message(self, event=None):
        msg = self.entry.get()
        if msg.strip():
            self.send_json({"type": "chat", "user": self.username, "message": msg})
            self.entry.delete(0, tk.END)

    def make_call(self):
        target = simpledialog.askstring("Call", "Who do you want to call?")
        if target:
            self.send_json({"type": "call_request", "from": self.username, "to": target})
            self.add_message(f"📞 Calling {target}...")

    def incoming_call(self, caller):
        popup = tk.Toplevel(self.root)
        popup.title("Incoming Call")
        tk.Label(popup, text=f"📞 Incoming call from {caller}", font=("Arial", 12)).pack(pady=10)

        def accept():
            self.send_json({"type": "call_response", "from": self.username, "to": caller, "response": "accept"})
            popup.destroy()
            self.start_call_window(caller)

        def decline():
            self.send_json({"type": "call_response", "from": self.username, "to": caller, "response": "decline"})
            popup.destroy()

        tk.Button(popup, text="✅ Accept", command=accept).pack(side="left", padx=20, pady=10)
        tk.Button(popup, text="❌ Decline", command=decline).pack(side="right", padx=20, pady=10)

    def start_call_window(self, peer):
        call_win = tk.Toplevel(self.root)
        call_win.title(f"Call with {peer}")
        tk.Label(call_win, text=f"In call with {peer}", font=("Arial", 12)).pack(pady=10)

        def end_call():
            self.send_json({"type": "end_call", "from": self.username, "to": peer})
            call_win.destroy()

        tk.Button(call_win, text="End Call", command=end_call).pack(pady=20)

    def add_message(self, msg):
        self.text_area.config(state="normal")
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.config(state="disabled")

    def listen_server(self):
        buffer = ""
        while True:
            try:
                data = self.sock.recv(1024).decode("utf-8")
                if not data:
                    break
                buffer += data
                while "\n" in buffer:
                    msg, buffer = buffer.split("\n", 1)
                    if msg.strip():
                        self.handle_message(json.loads(msg))
            except Exception as e:
                print("Error:", e)
                break

    def handle_message(self, data):
        msg_type = data.get("type")
        if msg_type == "chat":
            self.add_message(f"{data['user']}: {data['message']}")
        elif msg_type == "join":
            self.add_message(f"✅ {data['user']} has entered the chat")
        elif msg_type == "call_request":
            self.incoming_call(data["from"])
        elif msg_type == "call_response":
            if data["response"] == "accept":
                self.add_message(f"📞 {data['from']} accepted the call")
                self.start_call_window(data["from"])
            else:
                self.add_message(f"❌ {data['from']} declined the call")
        elif msg_type == "end_call":
            self.add_message(f"🔴 Call with {data['from']} ended")

    def on_close(self):
        self.sock.close()
        self.root.destroy()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("server_ip")
    parser.add_argument("username")
    args = parser.parse_args()

    Client(args.server_ip, 1060, args.username)
