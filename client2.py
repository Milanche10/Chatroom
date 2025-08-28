# client2.py
"""
SecureTalk client:
- GUI (tkinter)
- WebSocket signaling (websockets)
- Per-peer E2E using PyNaCl Box (X25519)
- File send/receive (per-peer encrypted)
- Audio call over UDP using Box encrypt/decrypt per-packet
Design notes:
- Uses a thread-safe queue.Queue for sending payloads from GUI thread to asyncio websocket loop.
- Keeps username -> user_id map for calling by username.
"""

import asyncio
import base64
import json
import queue
import socket
import threading
import uuid
from datetime import datetime, timezone
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox

import numpy as np
import sounddevice as sd
import websockets
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey

SERVER_WS = "ws://127.0.0.1:8765/ws"
AUDIO_RATE = 48000
BLOCK = 960
AUDIO_DTYPE = np.int16

def now_iso():
    return datetime.now(timezone.utc).isoformat()

class EncryptedAudioCall:
    """Simple encrypted UDP audio stream using NaCl Box (nonce per packet)."""
    def __init__(self, box: Box, local_port: int = 0):
        self.box = box
        self.running = False
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(('', local_port))
        self.local_port = self.udp.getsockname()[1]
        self.peer = None
        self.play_stream = None
        self.cap_stream = None

    def set_peer(self, host: str, port: int):
        self.peer = (host, int(port))

    def start(self):
        if self.running:
            return
        self.running = True
        # create audio streams
        self.play_stream = sd.OutputStream(samplerate=AUDIO_RATE, channels=1, dtype=AUDIO_DTYPE, blocksize=BLOCK)
        self.play_stream.start()
        self.cap_stream = sd.InputStream(samplerate=AUDIO_RATE, channels=1, dtype=AUDIO_DTYPE, blocksize=BLOCK, callback=self._capture_cb)
        self.cap_stream.start()
        threading.Thread(target=self._recv_loop, daemon=True).start()

    def _capture_cb(self, indata, frames, time, status):
        if not self.running or not self.peer:
            return
        pcm = indata.tobytes()
        nonce = np.random.bytes(24)
        cipher = self.box.encrypt(pcm, nonce)
        try:
            self.udp.sendto(cipher, self.peer)
        except Exception:
            pass

    def _recv_loop(self):
        while self.running:
            try:
                data, _ = self.udp.recvfrom(8192)
                pcm = self.box.decrypt(data)
                audio = np.frombuffer(pcm, dtype=AUDIO_DTYPE)
                self.play_stream.write(audio)
            except Exception:
                continue

    def stop(self):
        self.running = False
        try:
            if self.cap_stream:
                self.cap_stream.stop(); self.cap_stream.close()
            if self.play_stream:
                self.play_stream.stop(); self.play_stream.close()
        except Exception:
            pass
        try:
            self.udp.close()
        except Exception:
            pass

class SecureTalkClient:
    def __init__(self, username: str, room: str):
        # identity
        self.username = username
        self.room = room or "lobby"
        self.user_id = None

        # crypto
        self.dh_priv = PrivateKey.generate()
        self.dh_pub = self.dh_priv.public_key
        self.sign_priv = SigningKey.generate()
        self.sign_pub = self.sign_priv.verify_key

        # peer state
        self.peers_dh = {}         # user_id -> PublicKey
        self.peers_sign = {}       # user_id -> VerifyKey
        self.peer_boxes = {}       # user_id -> Box (our_priv, their_pub)
        self.username_to_uid = {}  # username -> user_id

        # call state
        self.call: EncryptedAudioCall | None = None
        self.active_call_with: str | None = None

        # transport queue (thread-safe)
        self.sync_send_q = queue.Queue()

        # GUI
        self.root = tk.Tk()
        self.root.title(f"SecureTalk — {self.username}")
        self._build_gui()

        # background loop thread handle
        self.ws_thread = None

    def _build_gui(self):
        frm_top = ttk.Frame(self.root, padding=8)
        frm_top.pack(fill="x")
        ttk.Label(frm_top, text=f"Korisnik: {self.username}").pack(side="left")
        self.room_var = tk.StringVar(value=self.room)
        ttk.Entry(frm_top, textvariable=self.room_var, width=20).pack(side="left", padx=8)
        ttk.Button(frm_top, text="Join sobu", command=self.join_room).pack(side="left")
        ttk.Button(frm_top, text="Osveži članove", command=self.refresh_members).pack(side="left", padx=6)

        frm_mid = ttk.Frame(self.root, padding=8)
        frm_mid.pack(fill="both", expand=True)
        self.chat = tk.Text(frm_mid, state="disabled", height=18, wrap="word")
        self.chat.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(frm_mid, command=self.chat.yview)
        self.chat.configure(yscrollcommand=sb.set)
        sb.pack(side="left", fill="y")

        right = ttk.Frame(frm_mid)
        right.pack(side="left", fill="y", padx=8)
        ttk.Button(right, text="Pozovi korisnika", command=self.call_user).pack(fill="x", pady=2)
        ttk.Button(right, text="Završi poziv", command=self.end_call).pack(fill="x", pady=2)
        ttk.Button(right, text="Pošalji fajl", command=self.send_file).pack(fill="x", pady=2)

        frm_bottom = ttk.Frame(self.root, padding=8)
        frm_bottom.pack(fill="x")
        self.msg_var = tk.StringVar()
        self.ttl_var = tk.StringVar(value="0")
        ttk.Entry(frm_bottom, textvariable=self.msg_var, width=60).pack(side="left", padx=(0,6))
        ttk.Label(frm_bottom, text="TTL(ms):").pack(side="left")
        ttk.Entry(frm_bottom, textvariable=self.ttl_var, width=8).pack(side="left", padx=(0,6))
        ttk.Button(frm_bottom, text="Pošalji", command=self.send_message).pack(side="left")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def log(self, text: str):
        self.chat.config(state="normal")
        self.chat.insert("end", f"{text}\n")
        self.chat.see("end")
        self.chat.config(state="disabled")

    # ---- crypto helpers ----
    def _ensure_box(self, peer_id: str):
        if peer_id in self.peer_boxes:
            return self.peer_boxes[peer_id]
        pub = self.peers_dh.get(peer_id)
        if not pub:
            return None
        box = Box(self.dh_priv, pub)
        self.peer_boxes[peer_id] = box
        return box

    def _encrypt_for(self, peer_id: str, plaintext: bytes) -> str:
        box = self._ensure_box(peer_id)
        if not box:
            raise RuntimeError("Peer key missing")
        nonce = np.random.bytes(24)
        ct = box.encrypt(plaintext, nonce)
        return base64.b64encode(ct).decode()

    def _decrypt_from(self, peer_id: str, b64cipher: str) -> bytes:
        box = self._ensure_box(peer_id)
        if not box:
            raise RuntimeError("No session with peer")
        ct = base64.b64decode(b64cipher.encode())
        pt = box.decrypt(ct)
        return pt

    # ---- websocket loop (runs in background thread via asyncio) ----
    async def _ws_loop(self):
        async with websockets.connect(SERVER_WS, max_size=20_000_000) as ws:
            self.ws = ws
            # receive hello
            msg = json.loads(await ws.recv())
            self.user_id = msg["user_id"]
            self.log(f"• Povezano (user_id={self.user_id})")

            # register with public keys
            await ws.send(json.dumps({
                "type": "register",
                "username": self.username,
                "pub_dh": base64.b64encode(bytes(self.dh_pub)).decode(),
                "pub_sign": base64.b64encode(bytes(self.sign_pub)).decode()
            }))
            # wait register_ok
            try:
                _ = json.loads(await ws.recv())
            except Exception:
                pass

            # join initial room
            await ws.send(json.dumps({"type": "join_room", "room": self.room}))

            loop = asyncio.get_event_loop()

            async def sender_task():
                # send items from sync_send_q (thread-safe queue) to websocket
                while True:
                    # blocking .get executed in executor to not block event loop
                    payload = await loop.run_in_executor(None, self.sync_send_q.get)
                    # ensure JSON serializable
                    try:
                        await ws.send(json.dumps(payload))
                    except Exception:
                        # endpoint closed
                        break

            async def receiver_task():
                while True:
                    raw = await ws.recv()
                    data = json.loads(raw)
                    await self._handle_server(data)

            await asyncio.gather(sender_task(), receiver_task())

    async def _handle_server(self, data: dict):
        t = data.get("type")
        if t == "room_joined":
            room = data.get("room")
            members = data.get("members", [])
            self.room = room
            # rebuild maps
            self.username_to_uid.clear()
            for m in members:
                uid = m["user_id"]
                uname = m.get("username")
                if uname:
                    self.username_to_uid[uname] = uid
                # store peer public keys if not us
                if uid != self.user_id and m.get("pub_dh"):
                    try:
                        self.peers_dh[uid] = PublicKey(base64.b64decode(m["pub_dh"]))
                        self.peers_sign[uid] = VerifyKey(base64.b64decode(m["pub_sign"]))
                        # remove old box to force re-derive
                        self.peer_boxes.pop(uid, None)
                    except Exception:
                        pass
            self.log(f"• Ušao si u sobu '{room}'. Članova: {len(members)}")
            # show roster
            if members:
                names = [m.get("username", m["user_id"][:6]) for m in members]
                self.log("Roster: " + ", ".join(names))

        elif t == "presence":
            ev = data.get("event")
            u = data.get("user", {})
            uid = u.get("user_id")
            uname = u.get("username")
            if ev == "join":
                if uname:
                    self.username_to_uid[uname] = uid
                if uid != self.user_id and u.get("pub_dh"):
                    try:
                        self.peers_dh[uid] = PublicKey(base64.b64decode(u["pub_dh"]))
                        self.peers_sign[uid] = VerifyKey(base64.b64decode(u["pub_sign"]))
                        self.peer_boxes.pop(uid, None)
                    except Exception:
                        pass
                self.log(f"✅ {uname or uid[:6]} se priključio.")
            elif ev == "leave":
                if uname:
                    self.username_to_uid.pop(uname, None)
                self.peers_dh.pop(uid, None)
                self.peers_sign.pop(uid, None)
                self.peer_boxes.pop(uid, None)
                if self.active_call_with == uid:
                    self._end_call_local()
                self.log(f"❌ {uname or uid[:6]} je napustio sobu.")

        elif t == "message":
            frm = data.get("from")
            cipher = data.get("cipher")
            try:
                pt = self._decrypt_from(frm, cipher)
                text = pt.decode("utf-8")
            except Exception:
                text = "⚠️ [Neuspešno dešifrovanje]"
            # show message: if username known map it
            uname = None
            for name, uid in self.username_to_uid.items():
                if uid == frm:
                    uname = name; break
            label = uname if uname else frm[:6]
            self.log(f"{label}: {text}")

        elif t == "file":
            frm = data.get("from")
            cipher_meta = data.get("cipher_meta")
            cipher_chunks = data.get("cipher_chunks", [])
            try:
                box = self._ensure_box(frm)
                meta = json.loads(box.decrypt(base64.b64decode(cipher_meta)).decode())
                fname = meta.get("filename", f"file_{now_iso()}")
                chunk_b64 = cipher_chunks[0]
                filedata = box.decrypt(base64.b64decode(chunk_b64))
                # save to current dir with unique name
                outname = f"recv_{fname}"
                with open(outname, "wb") as f:
                    f.write(filedata)
                uname = None
                for name, uid in self.username_to_uid.items():
                    if uid == frm:
                        uname = name; break
                self.log(f"📎 Primljen fajl od {uname or frm[:6]}: {outname}")
            except Exception:
                self.log("⚠️ Primljen fajl - neuspešno dešifrovanje")

        elif t in ("call_invite", "call_answer", "call_end", "call_ice"):
            # normalized: server forwards "from" as user_id
            if t == "call_invite":
                frm = data.get("from")
                udp_host = data.get("udp_host", None) or data.get("udp_host") or data.get("udp_host")
                udp_port = data.get("udp_port")
                # automatically accept for MVP (could prompt user)
                box = self._ensure_box(frm)
                if not box:
                    self.log("⚠️ Poziv: nemamo kripto sesiju sa peer-om.")
                    return
                # start call and set peer
                self.call = EncryptedAudioCall(box)
                self.call.start()
                # set peer address (we expect peer to send their host/port)
                host = udp_host or self._local_ip_guess()
                if udp_port:
                    self.call.set_peer(host, udp_port)
                self.local_udp_port = self.call.local_port
                self.active_call_with = frm
                self.log(f"📞 Poziv primljen od {self._username_of(frm) or frm[:6]}")
                # respond
                self.sync_send_q.put({
                    "type": "call_answer",
                    "to": frm,
                    "udp_host": self._local_ip_guess(),
                    "udp_port": self.local_udp_port,
                    "ok": True
                })
            elif t == "call_answer":
                frm = data.get("from")
                ok = data.get("ok", False)
                if ok and self.call and self.active_call_with == frm:
                    host = data.get("udp_host") or self._local_ip_guess()
                    port = data.get("udp_port")
                    # set peer and start audio if not yet
                    self.call.set_peer(host, port)
                    self.log(f"📞 Poziv povezan sa {self._username_of(frm) or frm[:6]}")
                else:
                    self.log("❌ Poziv odbijen ili greška")
            elif t == "call_end":
                frm = data.get("from")
                if self.active_call_with == frm:
                    self._end_call_local()
                    self.log("🔴 Poziv završen (peer).")

        elif t == "room_members":
            members = data.get("members", [])
            names = [m.get("username", m.get("user_id")[:6]) for m in members]
            self.log(f"• Članovi sobe ({data.get('room')}): {', '.join(names)}")

        elif t == "error":
            self.log(f"⚠️ Server error: {data.get('message')}")

    # ---- helper to resolve username from uid ----
    def _username_of(self, uid: str):
        for name, id_ in self.username_to_uid.items():
            if id_ == uid:
                return name
        return None

    def _local_ip_guess(self) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip

    # ---- GUI actions -> push to sync_send_q for websocket sender ----
    def join_room(self):
        room = self.room_var.get().strip() or "lobby"
        # clear local caches for new room
        self.peers_dh.clear(); self.peers_sign.clear(); self.peer_boxes.clear(); self.username_to_uid.clear()
        self.sync_send_q.put({"type": "join_room", "room": room})
        self.log(f"• Tražim pristup sobi '{room}'...")

    def refresh_members(self):
        self.sync_send_q.put({"type": "room_members"})

    def send_message(self):
        msg = self.msg_var.get().strip()
        if not msg:
            return
        # create per-peer ciphertext mapping
        cipher_dict = {}
        for uname, uid in self.username_to_uid.items():
            if uid == self.user_id:
                continue
            try:
                cipher = self._encrypt_for(uid, msg.encode("utf-8"))
                cipher_dict[uid] = cipher
            except Exception:
                # skip peers without keys
                continue
        if not cipher_dict:
            self.log("⚠️ Nema drugih članova ili nema kripto ključeva.")
            return
        payload = {
            "type": "message",
            "cipher_dict": cipher_dict,
            "msg_id": str(uuid.uuid4()),
            "ttl_ms": int(self.ttl_var.get() or 0)
        }
        # show our own message immediately
        self.log(f"Ja: {msg}")
        self.msg_var.set("")
        self.sync_send_q.put(payload)

    def send_file(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            messagebox.showerror("Greška", str(e))
            return
        # prepare per-peer encryption
        for uname, uid in self.username_to_uid.items():
            if uid == self.user_id:
                continue
            box = self._ensure_box(uid)
            if not box:
                continue
            cipher_meta = base64.b64encode(box.encrypt(json.dumps({"filename": path.split("/")[-1]}).encode(), np.random.bytes(24))).decode()
            cipher_chunk = base64.b64encode(box.encrypt(data, np.random.bytes(24))).decode()
            payload = {"type": "file", "cipher_dict": {uid: {"cipher_meta": cipher_meta, "cipher_chunks": [cipher_chunk]}}}
            self.sync_send_q.put(payload)
        self.log(f"📎 Poslat fajl: {path.split('/')[-1]}")

    def call_user(self):
        uname = simpledialog.askstring("Poziv", "Unesite username:").strip() if self.root else None
        if not uname:
            return
        target_uid = self.username_to_uid.get(uname)
        if not target_uid:
            self.log(f"⚠️ Korisnik {uname} nije dostupan.")
            return
        box = self._ensure_box(target_uid)
        if not box:
            self.log("⚠️ Nema kripto sesije sa ciljanim korisnikom.")
            return
        # start local audio call
        self.call = EncryptedAudioCall(box)
        self.call.start()
        self.local_udp_port = self.call.local_port
        self.active_call_with = target_uid
        # send invite using target_uid (server accepts uid or username)
        payload = {"type": "call_invite", "to": target_uid, "udp_host": self._local_ip_guess(), "udp_port": self.local_udp_port}
        self.sync_send_q.put(payload)
        self.log(f"📞 Poziv upućen ka {uname}")

    def end_call(self):
        if not self.active_call_with:
            return
        payload = {"type": "call_end", "to": self.active_call_with}
        self.sync_send_q.put(payload)
        self._end_call_local()
        self.log("🔴 Poziv završen (ja).")

    def _end_call_local(self):
        if self.call:
            try:
                self.call.stop()
            except Exception:
                pass
        self.call = None
        self.active_call_with = None

    def on_close(self):
        if messagebox.askokcancel("Izlaz", "Zatvori klijent?"):
            try:
                if self.call:
                    self.call.stop()
            except Exception:
                pass
            # attempt to leave room before exit
            try:
                self.sync_send_q.put({"type": "leave_room"})
            except Exception:
                pass
            self.root.destroy()

    # ---- run ----
    def run(self):
        # start websocket thread (runs asyncio loop)
        def _thread_run():
            asyncio.run(self._ws_loop())
        self.ws_thread = threading.Thread(target=_thread_run, daemon=True)
        self.ws_thread.start()
        # start GUI mainloop
        self.root.mainloop()


if __name__ == "__main__":
    uname = simpledialog.askstring("SecureTalk", "Unesite username:")
    if not uname:
        uname = f"user_{uuid.uuid4().hex[:6]}"
    room = simpledialog.askstring("Soba", "Unesite sobu (prazno = lobby)") or "lobby"
    client = SecureTalkClient(uname, room)
    client.run()