# server2.py
"""
SecureTalk signaling server (FastAPI + WebSocket)
Funkcije:
- registracija (username + javni ključevi)
- sobe (join/leave, roster)
- presence notifikacije (join/leave)
- message forwarding (per-peer ciphertext)
- file forwarding (per-peer ciphertext_meta + chunks)
- call signaling (call_invite, call_answer, call_end, call_ice)
Server prihvata 'to' polje kao user_id ili username (traži u USERS).
"""

import asyncio
import json
import uuid
from typing import Dict, Any, Set, Optional
from datetime import datetime, timezone

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="SecureTalk Server")

# Allow local dev CORS for testing with GUI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_headers=["*"],
    allow_methods=["*"],
)

# In-memory state
USERS: Dict[str, Dict[str, Any]] = {}   # user_id -> { username, ws, room, pub_dh, pub_sign, joined_at }
ROOMS: Dict[str, Set[str]] = {}         # room -> set(user_id)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

async def send_json(ws: WebSocket, payload: dict):
    try:
        await ws.send_text(json.dumps(payload, ensure_ascii=False))
    except Exception:
        # WebSocket may be closed; caller handles cleanup
        raise

async def notify_room(room: str, payload: dict, exclude_user_id: Optional[str] = None):
    """Send payload to all users in room except exclude"""
    if not room:
        return
    members = list(ROOMS.get(room, set()))
    for uid in members:
        if exclude_user_id and uid == exclude_user_id:
            continue
        uinfo = USERS.get(uid)
        if not uinfo:
            continue
        try:
            await send_json(uinfo["ws"], payload)
        except Exception:
            # ignore here; cleanup will happen on disconnect/finally
            pass

def join_room(user_id: str, room: str):
    if room not in ROOMS:
        ROOMS[room] = set()
    ROOMS[room].add(user_id)
    USERS[user_id]["room"] = room

def leave_room(user_id: str):
    room = USERS[user_id].get("room")
    if room and room in ROOMS:
        ROOMS[room].discard(user_id)
        if not ROOMS[room]:
            del ROOMS[room]
    USERS[user_id]["room"] = None

def room_roster(room: str):
    members = []
    for uid in ROOMS.get(room, set()):
        u = USERS.get(uid)
        if not u:
            continue
        members.append({
            "user_id": uid,
            "username": u.get("username"),
            "pub_dh": u.get("pub_dh"),
            "pub_sign": u.get("pub_sign"),
        })
    return members

def find_user_by_username(username: str) -> Optional[str]:
    """Return user_id if username found, else None"""
    for uid, info in USERS.items():
        if info.get("username") == username:
            return uid
    return None

@app.get("/")
async def index():
    return HTMLResponse("<h3>SecureTalk signaling server radi ✅</h3>")

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    user_id = str(uuid.uuid4())
    USERS[user_id] = {
        "username": None,
        "ws": ws,
        "room": None,
        "pub_dh": None,
        "pub_sign": None,
        "joined_at": now_iso(),
    }
    try:
        # greet
        await send_json(ws, {"type": "hello", "user_id": user_id, "server_time": now_iso()})
        buffer = ""
        while True:
            # receive text (assume client sends full JSON per ws.send)
            text = await ws.receive_text()
            buffer += text
            # parse JSON (we expect whole message)
            data = json.loads(buffer)
            buffer = ""

            mtype = data.get("type")

            # Register - client sends username and public keys
            if mtype == "register":
                USERS[user_id]["username"] = data.get("username")
                USERS[user_id]["pub_dh"] = data.get("pub_dh")
                USERS[user_id]["pub_sign"] = data.get("pub_sign")
                await send_json(ws, {"type": "register_ok", "user_id": user_id})

            # Join room
            elif mtype == "join_room":
                room = data.get("room") or "lobby"
                prev = USERS[user_id].get("room")
                if prev and prev != room:
                    leave_room(user_id)
                join_room(user_id, room)
                # send roster to the joining client
                await send_json(ws, {"type": "room_joined", "room": room, "members": room_roster(room)})
                # notify others in room
                await notify_room(room, {
                    "type": "presence",
                    "event": "join",
                    "user": {
                        "user_id": user_id,
                        "username": USERS[user_id]["username"],
                        "pub_dh": USERS[user_id]["pub_dh"],
                        "pub_sign": USERS[user_id]["pub_sign"],
                    }
                }, exclude_user_id=user_id)

            # Leave room
            elif mtype == "leave_room":
                old = USERS[user_id].get("room")
                leave_room(user_id)
                if old:
                    await notify_room(old, {
                        "type": "presence",
                        "event": "leave",
                        "user": {"user_id": user_id, "username": USERS[user_id]["username"]}
                    }, exclude_user_id=user_id)
                await send_json(ws, {"type": "left_ok"})

            # Message forwarding: expects 'cipher_dict': {peer_id: cipher}
            elif mtype == "message":
                cipher_dict = data.get("cipher_dict") or {}
                # Support legacy single-target "to" + "cipher"
                if data.get("to") and data.get("cipher"):
                    cipher_dict = {data.get("to"): data.get("cipher")}
                for peer_id, cipher in cipher_dict.items():
                    uinfo = USERS.get(peer_id)
                    if uinfo:
                        payload = {
                            "type": "message",
                            "from": user_id,
                            "cipher": cipher,
                            "msg_id": data.get("msg_id"),
                            "ttl_ms": data.get("ttl_ms"),
                            "ts": now_iso(),
                        }
                        try:
                            await send_json(uinfo["ws"], payload)
                        except Exception:
                            pass

            # File forwarding: expects cipher_dict: {peer_id: {cipher_meta, cipher_chunks}}
            elif mtype == "file":
                cipher_dict = data.get("cipher_dict") or {}
                # backward compatibility: single-target fields
                if data.get("to") and (data.get("cipher_meta") or data.get("cipher_chunks")):
                    cipher_dict = {data.get("to"): {"cipher_meta": data.get("cipher_meta"), "cipher_chunks": data.get("cipher_chunks")}}
                for peer_id, cdata in cipher_dict.items():
                    uinfo = USERS.get(peer_id)
                    if uinfo:
                        payload = {
                            "type": "file",
                            "from": user_id,
                            "cipher_meta": cdata.get("cipher_meta"),
                            "cipher_chunks": cdata.get("cipher_chunks"),
                            "ts": now_iso(),
                        }
                        try:
                            await send_json(uinfo["ws"], payload)
                        except Exception:
                            pass

            # Call signaling and similar: 'to' can be user_id or username
            elif mtype in ("call_invite", "call_answer", "call_end", "call_ice"):
                to_field = data.get("to")
                target_uid = None
                target_info = None
                # if to_field is a UID present in USERS
                if to_field in USERS:
                    target_uid = to_field
                    target_info = USERS.get(target_uid)
                else:
                    # try username lookup
                    lookup = find_user_by_username(to_field)
                    if lookup:
                        target_uid = lookup
                        target_info = USERS.get(lookup)
                if target_info:
                    fwd = dict(data)
                    fwd["from"] = user_id
                    # preserve 'to' as the UID (so client knows who sent)
                    fwd["to"] = target_uid
                    try:
                        await send_json(target_info["ws"], fwd)
                    except Exception:
                        pass

            # room_members request
            elif mtype == "room_members":
                room = USERS[user_id].get("room") or "lobby"
                await send_json(ws, {"type": "room_members", "room": room, "members": room_roster(room)})

            else:
                await send_json(ws, {"type": "error", "message": f"Unknown type: {mtype}"})

    except WebSocketDisconnect:
        # client disconnected
        pass
    except Exception:
        # ignore other errors per-connection
        pass
    finally:
        # cleanup: notify room about leave
        u = USERS.get(user_id)
        if u:
            room = u.get("room")
            username = u.get("username")
            if room:
                await notify_room(room, {"type": "presence", "event": "leave", "user": {"user_id": user_id, "username": username}}, exclude_user_id=user_id)
            # remove user
            USERS.pop(user_id, None)

if __name__ == "__main__":
    # run without reload in production-like mode
    uvicorn.run("server2:app", host="0.0.0.0", port=8765, reload=False)
