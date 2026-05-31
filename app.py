# -*- coding: utf-8 -*-
# MASJON BOT - نسخة تعمل على RENDER

import json
import asyncio
import aiohttp
import ssl
import gzip
import time
import threading
import requests
import logging
import os
import sys
from datetime import datetime, timedelta
import jwt as pyjwt
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
from protobuf_decoder.protobuf_decoder import Parser
from flask import Flask, request, jsonify

app = Flask(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.ERROR)

# ----------------------------------------
JWT_UPDATE_INTERVAL = 600
TEMP_UID = "4714386498"
TEMP_PASSWORD = "MASJONDGIJS"
GAME_VERSION = "OB53"

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

users_file = "temp_friends.json"
jwt_cache_file = "jwt_cache.json"
accs_file = "accs.json"

_current_jwt_token = None
_jwt_lock = threading.Lock()
_clis = []
_masjon_tasks = {}
_loop = None
_accounts_loaded = False

# متغيرات للتشغيل على Render
_gunicorn_worker = False
_initialized = False

def is_gunicorn():
    """التحقق إذا كنا نعمل تحت Gunicorn"""
    return 'gunicorn' in os.environ.get('SERVER_SOFTWARE', '')

def silent_print(message, force=False):
    """طباعة فقط إذا كانت force=True"""
    if force:
        print(message, flush=True)

# ========================================
# دوال JWT
# ========================================

def save_jwt_to_cache(jwt_token):
    try:
        cache_data = {"jwt": jwt_token, "last_update": int(time.time()), "expires_at": int(time.time()) + 3600}
        with open(jwt_cache_file, "w") as f:
            json.dump(cache_data, f, indent=4)
        return True
    except:
        return False

def load_jwt_from_cache():
    try:
        if os.path.exists(jwt_cache_file):
            with open(jwt_cache_file, "r") as f:
                cache_data = json.load(f)
                jwt = cache_data.get("jwt")
                if jwt and len(jwt) > 50:
                    return jwt
        return None
    except:
        return None

async def extract_new_jwt():
    global _current_jwt_token
    
    try:
        async with aiohttp.ClientSession() as session:
            at, oid = await g_access(TEMP_UID, TEMP_PASSWORD, session)
            if not at:
                return None
            
            dT = bytes.fromhex('1a13323032352d31312d32362030313a35313a3238220966726565206669726528013a07312e3132302e31'
                               '4232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e323032323035'
                               '31382e313134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960'
                               '800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e3220415658'
                               '2041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f'
                               '70656e474c20455320332e329a012b476f6f676c657c36323566373136662d393161372d343935622d'
                               '396631362d303866653964336336353333a2010e3137362e32382e3133392e313835aa01026172b2012'
                               '03433303632343537393364653836646134323561353263616164663231656564ba010134c2010848616'
                               'e6468656c64ca010d4f6e65506c7573204135303130ea014063363961653230386661643732373338623'
                               '637346232383437623530613361316466613235643161313966616537343566633736616334613065343'
                               '134633934f00101ca020c4d544e2f537061636574656cd2020457494649ca03203161633462383065636'
                               '630343738613434323033626638666163363132306635e003b5ee02e8039a8002f003af13f80384078004'
                               'a78f028804b5ee029004a78f029804b5ee02b00404c80401d2043d2f646174612f6170702f636f6d2e64'
                               '74732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f6c6962'
                               '2f61726de00401ea045f65363261623935333464386662356662303138646233333861636233333439317'
                               'c2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b4'
                               '3376a4c2d574f7952413d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139'
                               '303236a80503b205094f70656e474c455332b805ff01c00504e005be7eea05093372645f7061727479f2'
                               '05704b717348543857393347646347335a6f7a454e6646775648746d377171316552554e6149444e6752'
                               '6f626f7a4942744c4f695943633459367a767670634943787a514632734f453463627974774c7334785a'
                               '62526e70524d706d5752514b6d654f35766373386e51594268777148374bf805e7e406880601900601'
                               '9a060134a2060134b2062213521146500e590349510e460900115843395f005b510f685b560a61075'
                               '76d0f0366')
            dT = dT.replace(b'2025-11-26 01:51:28', str(datetime.now())[:-7].encode())
            dT = dT.replace(b'c69ae208fad72738b674b2847b50a3a1dfa25d1a19fae745fc76ac4a0e414c94', at.encode())
            dT = dT.replace(b'4306245793de86da425a52caadf21eed', oid.encode())
            dT = dT.replace(b'1.120.1', b'1.123.8')
            pyl = bytes.fromhex(enc_aes(dT.hex()))
            
            raw = await major_login(pyl, session)
            if not raw:
                return None
            
            d = json.loads(decode_packet(raw.hex()))
            jwt_token = d['8']['data']
            
            if jwt_token and len(jwt_token) > 50:
                with _jwt_lock:
                    _current_jwt_token = jwt_token
                save_jwt_to_cache(jwt_token)
                return jwt_token
            return None
    except Exception as e:
        return None

def get_jwt_token():
    global _current_jwt_token
    with _jwt_lock:
        if _current_jwt_token:
            return _current_jwt_token
    
    cached_jwt = load_jwt_from_cache()
    if cached_jwt:
        with _jwt_lock:
            _current_jwt_token = cached_jwt
        return cached_jwt
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        token = loop.run_until_complete(extract_new_jwt())
        loop.close()
        return token
    except:
        return None

def refresh_jwt_if_needed(response_status, force=False):
    if force or response_status == 401:
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            new_token = loop.run_until_complete(extract_new_jwt())
            loop.close()
            return new_token is not None
        except:
            return False
    return True

def start_jwt_refresh_thread():
    def refresh_loop():
        while True:
            time.sleep(JWT_UPDATE_INTERVAL)
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(extract_new_jwt())
                loop.close()
            except:
                pass
    threading.Thread(target=refresh_loop, daemon=True).start()

# ----------------------------------------
# دوال التشفير (مختصرة)
# ----------------------------------------
def encrypt_id(player_id):
    result = []
    for i, char in enumerate(str(player_id)):
        result.append(str((int(char) + i) % 10))
    return ''.join(result)

def encrypt_api(payload):
    result = []
    for i in range(0, len(payload), 2):
        if i + 1 < len(payload):
            result.append(payload[i+1])
            result.append(payload[i])
        else:
            result.append(payload[i])
    return ''.join(result)

def user_agent():
    return "GarenaMSDK/5.5.2P3(SM-A125F;Android 14;en-US;USA;)"

def enc_aes(hexStr):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(bytes.fromhex(hexStr), AES.block_size)).hex()

def enc_packet(hexStr, k, iv):
    return AES.new(k, AES.MODE_CBC, iv).encrypt(pad(bytes.fromhex(hexStr), 16)).hex()

def enc_varint(n):
    if n < 0: return b''
    h = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n: b |= 0x80
        h.append(b)
        if not n: break
    return bytes(h)

def create_varint(field, value):
    return enc_varint((field << 3) | 0) + enc_varint(value)

def create_length(field, value):
    hdr = enc_varint((field << 3) | 2)
    enc = value.encode() if isinstance(value, str) else value
    return hdr + enc_varint(len(enc)) + enc

def create_proto(fields):
    pkt = bytearray()
    for f, v in fields.items():
        if isinstance(v, dict):
            nested = create_proto(v)
            pkt.extend(create_length(f, nested))
        elif isinstance(v, int):
            pkt.extend(create_varint(f, v))
        elif isinstance(v, (str, bytes)):
            pkt.extend(create_length(f, v))
    return pkt

def decode_hex(h):
    r = hex(h)[2:]
    return "0" + r if len(r) == 1 else r

def fix_parsed(parsed):
    d = {}
    for r in parsed:
        fd = {'wire_type': r.wire_type}
        if r.wire_type in ("varint", "string", "bytes"):
            fd['data'] = r.data
        elif r.wire_type == 'length_delimited':
            fd['data'] = fix_parsed(r.data.results)
        d[r.field] = fd
    return d

def decode_packet(hexInput):
    try:
        parsed = Parser().parse(hexInput)
        return json.dumps(fix_parsed(parsed))
    except:
        return None

def gen_pkt(pkt, n, k, iv):
    enc = enc_packet(pkt, k, iv)
    l = decode_hex(len(enc) // 2)
    if len(l) == 2: hdr = n + "000000"
    elif len(l) == 3: hdr = n + "00000"
    elif len(l) == 4: hdr = n + "0000"
    elif len(l) == 5: hdr = n + "000"
    else: hdr = n + "000000"
    return bytes.fromhex(hdr + l + enc)

def open_room(k, iv):
    f = {1: 2, 2: {1: 1, 2: 15, 3: 5, 4: "H4RDIXXX", 5: "1", 6: 12, 7: 1,
                    8: 1, 9: 1, 11: 1, 12: 2, 14: 36981056,
                    15: {1: "IDC3", 2: 126, 3: "ME"},
                    16: "\u0001\u0003\u0004\u0007\t\n\u000b\u0012\u000f\u000e\u0016\u0019\u001a \u001d",
                    18: 2368584, 27: 1, 34: "\u0000\u0001", 40: "en", 48: 1,
                    49: {1: 21}, 50: {1: 36981056, 2: 2368584, 5: 2}}}
    return gen_pkt(str(create_proto(f).hex()), '0E15', k, iv)

def spm_room(k, iv, uid):
    f = {1: 22, 2: {1: int(uid)}}
    return gen_pkt(str(create_proto(f).hex()), '0E15', k, iv)

async def g_access(u, p, session):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": user_agent(),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": str(u),
        "password": str(p),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    async with session.post(url, headers=headers, data=data, ssl=False, timeout=30) as resp:
        if resp.status == 200:
            js = await resp.json()
            return js.get('access_token'), js.get('open_id')
    return None, None

async def major_login(pyl, session):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = aiohttp.TCPConnector(ssl=ctx)
    async with aiohttp.ClientSession(connector=conn) as sess:
        headers = {
            'X-Unity-Version': '2022.3.47f1',
            'ReleaseVersion': 'OB53',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'User-Agent': 'UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Host': 'loginbp.ggpolarbear.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'deflate, gzip'
        }
        async with sess.post("https://loginbp.ggpolarbear.com/MajorLogin", headers=headers, data=pyl) as resp:
            raw = await resp.read()
            if resp.headers.get('Content-Encoding') == 'gzip':
                raw = gzip.decompress(raw)
            if resp.status in (200, 201):
                return raw
    return None

async def get_ports(tok, pyl, session):
    headers = {
        'Expect': '100-continue',
        'Authorization': f'Bearer {tok}',
        'X-Unity-Version': '2022.3.47f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB53',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
        'Host': 'clientbp.ggpolarbear.com',
        'Connection': 'close',
        'Accept-Encoding': 'deflate, gzip'
    }
    async with session.post("https://clientbp.ggpolarbear.com/GetLoginData", headers=headers, data=pyl, ssl=False) as resp:
        raw = await resp.read()
        d = json.loads(decode_packet(raw.hex()))
        a1, a2 = d['32']['data'], d['14']['data']
        return a1[:len(a1)-6], a1[len(a1)-5:], a2[:len(a2)-6], a2[len(a2)-5:]

def get_kiv(raw):
    class _runtime_version:
        class Domain: PUBLIC = 0
        @staticmethod
        def ValidateProtobufRuntimeVersion(*args, **kwargs): return True
    _runtime_version.ValidateProtobufRuntimeVersion()
    _sym_db = _symbol_database.Default()
    DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x10my_message.proto\">\n\tMyMessage\x12\x0f\n\x07\x66ield21\x18\x15 \x01(\x03\x12\x0f\n\x07\x66ield22\x18\x16 \x01(\x0c\x12\x0f\n\x07\x66ield23\x18\x17 \x01(\x0c\x62\x06proto3')
    _globals = globals()
    _builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
    _builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'my_message_pb2', _globals)
    MyMessage = _globals['MyMessage']
    m = MyMessage()
    m.ParseFromString(raw)
    ts = Timestamp()
    ts.FromNanoseconds(m.field21)
    return ts.seconds * 1_000_000_000 + ts.nanos, m.field22, m.field23

def build_auth(jwtTok, k, iv, ts):
    dec = pyjwt.decode(jwtTok, options={"verify_signature": False})
    enc = hex(dec['account_id'])[2:]
    tsH = decode_hex(ts)
    jH = jwtTok.encode().hex()
    hLen = hex(len(enc_packet(jH, k, iv)) // 2)[2:]
    padMap = {9: '0000000', 8: '00000000', 10: '000000', 7: '000000000'}
    pad = padMap.get(len(enc), '00000000')
    return f'0115{pad}{enc}{tsH}00000{hLen}' + enc_packet(jH, k, iv)

async def do_login(u, p, session):
    at, oid = await g_access(u, p, session)
    if not at: return None
    dT = bytes.fromhex('1a13323032352d31312d32362030313a35313a3238220966726565206669726528013a07312e3132302e31'
                       '4232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e323032323035'
                       '31382e313134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960'
                       '800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e3220415658'
                       '2041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f'
                       '70656e474c20455320332e329a012b476f6f676c657c36323566373136662d393161372d343935622d'
                       '396631362d303866653964336336353333a2010e3137362e32382e3133392e313835aa01026172b2012'
                       '03433303632343537393364653836646134323561353263616164663231656564ba010134c2010848616'
                       'e6468656c64ca010d4f6e65506c7573204135303130ea014063363961653230386661643732373338623'
                       '637346232383437623530613361316466613235643161313966616537343566633736616334613065343'
                       '134633934f00101ca020c4d544e2f537061636574656cd2020457494649ca03203161633462383065636'
                       '630343738613434323033626638666163363132306635e003b5ee02e8039a8002f003af13f80384078004'
                       'a78f028804b5ee029004a78f029804b5ee02b00404c80401d2043d2f646174612f6170702f636f6d2e64'
                       '74732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f6c6962'
                       '2f61726de00401ea045f65363261623935333464386662356662303138646233333861636233333439317'
                       'c2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b4'
                       '3376a4c2d574f7952413d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139'
                       '303236a80503b205094f70656e474c455332b805ff01c00504e005be7eea05093372645f7061727479f2'
                       '05704b717348543857393347646347335a6f7a454e6646775648746d377171316552554e6149444e6752'
                       '6f626f7a4942744c4f695943633459367a767670634943787a514632734f453463627974774c7334785a'
                       '62526e70524d706d5752514b6d654f35766373386e51594268777148374bf805e7e406880601900601'
                       '9a060134a2060134b2062213521146500e590349510e460900115843395f005b510f685b560a61075'
                       '76d0f0366')
    dT = dT.replace(b'2025-11-26 01:51:28', str(datetime.now())[:-7].encode())
    dT = dT.replace(b'c69ae208fad72738b674b2847b50a3a1dfa25d1a19fae745fc76ac4a0e414c94', at.encode())
    dT = dT.replace(b'4306245793de86da425a52caadf21eed', oid.encode())
    dT = dT.replace(b'1.120.1', b'1.123.8')
    pyl = bytes.fromhex(enc_aes(dT.hex()))
    raw = await major_login(pyl, session)
    if not raw: return None
    d = json.loads(decode_packet(raw.hex()))
    jwtTok = d['8']['data']
    ts, k, iv = get_kiv(raw)
    ip, port, ip2, port2 = await get_ports(jwtTok, pyl, session)
    auth = build_auth(jwtTok, k, iv, ts)
    return auth, k, iv, ip, port, ip2, port2

# ----------------------------------------
# حسابات الهجوم
# ----------------------------------------
class AsyncCli:
    def __init__(self, u, p):
        self.u = u
        self.p = p
        self.key = None
        self.iv = None
        self.reader1 = None
        self.writer1 = None
        self.reader2 = None
        self.writer2 = None
        self.alive = False
        self.task = None
        self.reconnect_attempts = 0
        self.last_heartbeat = time.time()
        self.keepalive_task = None

    def start(self):
        if self.task is None or self.task.done():
            self.task = asyncio.run_coroutine_threadsafe(self._run_with_keepalive(), _loop)

    async def _keep_alive(self):
        while self.alive:
            try:
                await asyncio.sleep(25)
                if self.writer2 and not self.writer2.is_closing():
                    heartbeat_pkt = open_room(self.key, self.iv)
                    self.writer2.write(heartbeat_pkt)
                    await self.writer2.drain()
                    self.last_heartbeat = time.time()
            except:
                break

    async def _run_with_keepalive(self):
        while True:
            try:
                await self._run()
                break
            except:
                self.alive = False
                if self.keepalive_task:
                    self.keepalive_task.cancel()
                await asyncio.sleep(3)
                self.reconnect_attempts += 1
                if self.reconnect_attempts > 10:
                    break

    async def _run(self):
        async with aiohttp.ClientSession() as session:
            res = await do_login(self.u, self.p, session)
            if not res:
                return
            
            auth, k, iv, ip, port, ip2, port2 = res
            self.key, self.iv = k, iv

            self.reader1, self.writer1 = await asyncio.open_connection(ip, int(port))
            self.writer1.write(bytes.fromhex(auth))
            await self.writer1.drain()
            await asyncio.sleep(0.3)
            
            try:
                await asyncio.wait_for(self.reader1.read(1024), timeout=5)
            except:
                pass

            self.reader2, self.writer2 = await asyncio.open_connection(ip2, int(port2))
            self.writer2.write(bytes.fromhex(auth))
            await self.writer2.drain()
            await asyncio.sleep(0.2)

            self.alive = True
            self.reconnect_attempts = 0
            self.keepalive_task = asyncio.create_task(self._keep_alive())

            while self.alive:
                try:
                    data = await asyncio.wait_for(self.reader2.read(4096), timeout=60)
                    if not data:
                        break
                except:
                    break
                    
    async def stop(self):
        self.alive = False
        if self.keepalive_task:
            self.keepalive_task.cancel()
        for writer in [self.writer1, self.writer2]:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass

def load_accounts():
    global _accounts_loaded, _clis
    
    if _accounts_loaded:
        return len(_clis)
    
    try:
        if not os.path.exists(accs_file):
            print(f"⚠️ {accs_file} غير موجود", flush=True)
            return 0
        
        with open(accs_file, "r") as f:
            accs = json.load(f)
        
        if not accs:
            print("⚠️ لا توجد حسابات في الملف", flush=True)
            return 0
        
        for u, p in accs.items():
            existing = any(c.u == u for c in _clis)
            if not existing:
                cli = AsyncCli(u, p)
                cli.start()
                _clis.append(cli)
                time.sleep(0.1)
        
        _accounts_loaded = True
        
        # الرسالة الوحيدة
        silent_print(f"\n✅ تم تشغيل كل الحسابات ({len(_clis)} حساب)", force=True)
        return len(_clis)
        
    except Exception as e:
        print(f"⚠️ خطأ: {e}", flush=True)
        return 0

def get_active_bots():
    return [c for c in _clis if c.alive]

async def masjon_spam_loop(uid, stop_event):
    total_sent = 0
    while not stop_event.is_set():
        active = [c for c in _clis if c.alive and c.writer2 and not c.writer2.is_closing()]
        
        if not active:
            await asyncio.sleep(1)
            continue
            
        for client in active:
            if stop_event.is_set():
                break
            try:
                roomPkt = open_room(client.key, client.iv)
                spmPkt = spm_room(client.key, client.iv, uid)
                if client.writer2 and not client.writer2.is_closing():
                    client.writer2.write(roomPkt)
                    await client.writer2.drain()
                    await asyncio.sleep(0.05)
                    for _ in range(10):
                        if stop_event.is_set():
                            break
                        client.writer2.write(spmPkt)
                        await client.writer2.drain()
                        total_sent += 1
                        await asyncio.sleep(0.05)
            except:
                pass
        
        await asyncio.sleep(0.3)
    
    return total_sent

def start_masjon(uid):
    if uid in _masjon_tasks:
        return False, "⚠️ هجوم يعمل بالفعل"
    stop = asyncio.Event()
    task = asyncio.run_coroutine_threadsafe(masjon_spam_loop(uid, stop), _loop)
    _masjon_tasks[uid] = (task, stop)
    return True, f"✅ بدأ الهجوم على {uid} بـ {len(get_active_bots())} بوت"

def stop_masjon(uid):
    if uid not in _masjon_tasks:
        return False, "❌ لا يوجد هجوم"
    task, stop = _masjon_tasks.pop(uid)
    stop.set()
    task.cancel()
    return True, f"🛑 تم إيقاف الهجوم"

def stop_all_masjon():
    targets = list(_masjon_tasks.keys())
    for uid in targets:
        stop_masjon(uid)
    return len(targets)

def get_masjon_tasks():
    return list(_masjon_tasks.keys())

# ========================================
# API Routes
# ========================================

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "running",
        "message": "MASJON BOT API",
        "accounts_loaded": _accounts_loaded,
        "total_accounts": len(_clis),
        "active_accounts": len(get_active_bots())
    })

@app.route('/stats', methods=['GET'])
def stats():
    return jsonify({
        "accounts_loaded": _accounts_loaded,
        "total_bots": len(_clis),
        "active_bots": len(get_active_bots()),
        "inactive_bots": len(_clis) - len(get_active_bots()),
        "active_masjon": len(_masjon_tasks),
        "masjon_targets": get_masjon_tasks()
    })

@app.route('/masjon/start', methods=['GET'])
def masjon_start():
    uid = request.args.get('uid', '')
    if not uid or not uid.isdigit():
        return jsonify({"success": False, "message": "UID غير صالح"})
    
    if not _accounts_loaded or len(get_active_bots()) == 0:
        return jsonify({"success": False, "message": "❌ لا توجد بوتات نشطة"})
    
    success, message = start_masjon(uid)
    return jsonify({"success": success, "message": message})

@app.route('/masjon/stop', methods=['GET'])
def masjon_stop():
    uid = request.args.get('uid', '')
    if not uid:
        return jsonify({"success": False, "message": "UID مطلوب"})
    success, message = stop_masjon(uid)
    return jsonify({"success": success, "message": message})

@app.route('/masjon/stopall', methods=['GET'])
def masjon_stop_all():
    count = stop_all_masjon()
    return jsonify({"success": True, "message": f"🛑 تم إيقاف {count} هجوم"})

@app.route('/masjon/list', methods=['GET'])
def masjon_list():
    return jsonify({"targets": get_masjon_tasks(), "count": len(get_masjon_tasks())})

# ========================================
# التشغيل الرئيسي - متوافق مع Gunicorn
# ========================================

def run_forever(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()

def init_system():
    """تهيئة النظام - تُستدعى مرة واحدة"""
    global _loop, _initialized
    
    if _initialized:
        return
    
    print("🚀 MASJON BOT بدء التشغيل...", flush=True)
    
    # إنشاء حلقة asyncio جديدة
    _loop = asyncio.new_event_loop()
    t = threading.Thread(target=run_forever, args=(_loop,), daemon=True)
    t.start()
    
    # انتظار قليل
    time.sleep(2)
    
    # تحميل الحسابات
    load_accounts()
    
    # استخراج JWT
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(extract_new_jwt())
        loop.close()
    except:
        pass
    
    # بدء خدمات الخلفية
    start_jwt_refresh_thread()
    
    _initialized = True
    print("✅ النظام جاهز!", flush=True)

# تهيئة النظام عند بدء التشغيل
# نستخدم threading.Timer للتأكد من أن التهيئة تعمل مع Gunicorn
def delayed_init():
    init_system()

# بدء التهيئة بعد ثانية
threading.Timer(1, delayed_init).start()

# للاختبار المحلي
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
