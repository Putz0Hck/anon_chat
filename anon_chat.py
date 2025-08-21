#!/usr/bin/env python3
"""
anon_chat.py
Chat de terminal com E2E (PyNaCl). Funciona como --listen (espera conexão)
ou --connect (conecta a um IP:PORT). Ideal para Termux/terminal.

Dependências: pynacl, pysocks (opcional)
Instalação: pip install pynacl pysocks
"""

import argparse
import socket
import threading
import json
import os
import sys
import time
from datetime import datetime, timezone
from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random as nacl_random
from nacl.encoding import Base64Encoder
import struct

# Optionally allow SOCKS proxy (e.g., Tor) via pysocks if installed
try:
    import socks  # pysocks
    SOCKS_AVAILABLE = True
except Exception:
    SOCKS_AVAILABLE = False

APP_DIR = os.path.expanduser("~/.anon_chat")
KEYFILE = os.path.join(APP_DIR, "keypair.json")
HISTORY_FILE = os.path.join(APP_DIR, "history.log")

FRAME_HDR = ">I"  # 4-byte length prefix


def ensure_app_dir():
    if not os.path.isdir(APP_DIR):
        os.makedirs(APP_DIR, exist_ok=True)


def save_keypair(privkey: bytes, pubkey: bytes):
    ensure_app_dir()
    data = {
        "private": Base64Encoder.encode(privkey).decode(),
        "public": Base64Encoder.encode(pubkey).decode()
    }
    with open(KEYFILE, "w") as f:
        json.dump(data, f)


def load_keypair():
    if os.path.exists(KEYFILE):
        with open(KEYFILE, "r") as f:
            data = json.load(f)
            priv = Base64Encoder.decode(data["private"].encode())
            pub = Base64Encoder.decode(data["public"].encode())
            return priv, pub
    return None, None


def generate_or_load_keys():
    priv, pub = load_keypair()
    if priv is None:
        key = PrivateKey.generate()
        priv = bytes(key)
        pub = bytes(key.public_key)
        save_keypair(priv, pub)
        print("[*] Nova chave gerada e salva em", KEYFILE)
    else:
        print("[*] Chave carregada de", KEYFILE)
    return priv, pub


def print_banner():
    print("="*60)
    print("Chat Anônimo — E2E")
    print("Aviso: metadados (IP, porta) ainda podem vazar sem proxy/Tor.")
    print("="*60)


def iso_now():
    return datetime.now(timezone.utc).astimezone().isoformat()


def save_history_line(line: str):
    ensure_app_dir()
    with open(HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def frame_send(sock: socket.socket, data: bytes):
    length = struct.pack(FRAME_HDR, len(data))
    sock.sendall(length + data)


def frame_recv(sock: socket.socket):
    hdr = recvall(sock, struct.calcsize(FRAME_HDR))
    if not hdr:
        return None
    (length,) = struct.unpack(FRAME_HDR, hdr)
    if length == 0:
        return b""
    return recvall(sock, length)


def recvall(sock: socket.socket, n: int):
    data = bytearray()
    while len(data) < n:
        try:
            packet = sock.recv(n - len(data))
        except Exception:
            return None
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)


def build_box(our_priv_bytes: bytes, their_pub_bytes: bytes):
    return Box(PrivateKey(our_priv_bytes), PublicKey(their_pub_bytes))


def send_public_key(sock: socket.socket, pubkey_bytes: bytes):
    """Envia a chave pública (em base64) como JSON não cifrado inicial."""
    msg = {"type": "pubkey", "public": Base64Encoder.encode(pubkey_bytes).decode()}
    payload = json.dumps(msg).encode()
    frame_send(sock, payload)


def recv_public_key(sock: socket.socket, timeout=10.0):
    """Recebe chave pública remota (não cifrada)"""
    sock.settimeout(timeout)
    try:
        raw = frame_recv(sock)
        if not raw:
            return None
        data = json.loads(raw.decode())
        if data.get("type") == "pubkey":
            their_pub = Base64Encoder.decode(data["public"].encode())
            return their_pub
        return None
    except Exception:
        return None
    finally:
        sock.settimeout(None)


def encrypt_message(box: Box, plaintext: bytes):
    nonce = nacl_random(Box.NONCE_SIZE)
    ciphertext = box.encrypt(plaintext, nonce)
    # ciphertext already contains nonce + cipher (PyNaCl Box.encrypt returns nonce + c)
    return ciphertext


def decrypt_message(box: Box, ciphertext: bytes):
    try:
        pt = box.decrypt(ciphertext)
        return pt
    except Exception:
        return None


def sender_thread(sock: socket.socket, box: Box, username: str):
    try:
        while True:
            text = input()
            if text.strip() == "":
                continue
            now = iso_now()
            message_obj = {
                "username": username,
                "timestamp": now,
                "message": text
            }
            plain = json.dumps(message_obj, ensure_ascii=False).encode("utf-8")
            cipher = encrypt_message(box, plain)
            frame_send(sock, cipher)
            # Save local history (clear text!). If you prefer to save encrypted, change here.
            hist_line = f"[{now}] {username} (me): {text}"
            print(hist_line)
            save_history_line(hist_line)
    except (KeyboardInterrupt, EOFError):
        print("\n[*] Saindo...")
        try:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        except:
            pass
        os._exit(0)


def receiver_thread(sock: socket.socket, box: Box):
    try:
        while True:
            data = frame_recv(sock)
            if data is None:
                print("\n[*] Conexão fechada pelo par.")
                os._exit(0)
            # decrypt
            pt = decrypt_message(box, data)
            if pt is None:
                print("[!] Falha ao descriptografar mensagem recebida.")
                continue
            try:
                obj = json.loads(pt.decode("utf-8"))
                now = obj.get("timestamp", iso_now())
                uname = obj.get("username", "unknown")
                message = obj.get("message", "")
                line = f"[{now}] {uname}: {message}"
                print("\n" + line)
                save_history_line(line)
            except Exception as e:
                print("[!] Mensagem recebida em formato inesperado.")
    except Exception:
        print("\n[*] Receiver encerrado.")
        os._exit(0)


def run_listen(bind_host, bind_port, username, socks_proxy=None):
    print_banner()
    priv, pub = generate_or_load_keys()
    s = None
    if socks_proxy and SOCKS_AVAILABLE:
        # Create a SOCKS-wrapped socket (used rarely in listen mode)
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, socks_proxy[0], socks_proxy[1])
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_host, bind_port))
    s.listen(1)
    print(f"[*] Ouvindo em {bind_host}:{bind_port} — aguarde conexão...")
    conn, addr = s.accept()
    print(f"[*] Conexão de {addr[0]}:{addr[1]}")
    # do public key exchange (unauthenticated)
    send_public_key(conn, pub)
    their_pub = recv_public_key(conn)
    if not their_pub:
        print("[!] Não recebeu chave pública do par. Fechando.")
        conn.close()
        return
    box = build_box(priv, their_pub)
    print("[*] Troca de chaves concluída. Chat seguro iniciado.")
    print("[*] Digite mensagens e pressione Enter.")
    # start threads
    t_recv = threading.Thread(target=receiver_thread, args=(conn, box), daemon=True)
    t_send = threading.Thread(target=sender_thread, args=(conn, box, username), daemon=True)
    t_recv.start()
    t_send.start()
    # wait
    t_recv.join()
    t_send.join()


def run_connect(remote_host, remote_port, username, socks_proxy=None, timeout=10.0):
    print_banner()
    priv, pub = generate_or_load_keys()
    if socks_proxy and SOCKS_AVAILABLE:
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, socks_proxy[0], socks_proxy[1])
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        print(f"[*] Conectando a {remote_host}:{remote_port} ...")
        s.connect((remote_host, remote_port))
    except Exception as e:
        print("[!] Falha ao conectar:", e)
        return
    s.settimeout(None)
    # Do handshake: first receive remote pubkey, then send ours (symmetrical either way)
    their_pub = recv_public_key(s)
    send_public_key(s, pub)
    if not their_pub:
        print("[!] Não recebeu chave pública do par. Fechando.")
        s.close()
        return
    box = build_box(priv, their_pub)
    print("[*] Troca de chaves concluída. Chat seguro iniciado.")
    print("[*] Digite mensagens e pressione Enter.")
    t_recv = threading.Thread(target=receiver_thread, args=(s, box), daemon=True)
    t_send = threading.Thread(target=sender_thread, args=(s, box, username), daemon=True)
    t_recv.start()
    t_send.start()
    t_recv.join()
    t_send.join()


def main():
    parser = argparse.ArgumentParser(description="Chat E2E anônimo para Termux/terminal")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--listen", action="store_true", help="Ficar ouvindo (esperar conexão)")
    group.add_argument("--connect", action="store_true", help="Conectar a um par (host:port)")
    parser.add_argument("--host", default="0.0.0.0", help="Host para ouvir ou conectar")
    parser.add_argument("--port", type=int, default=9000, help="Porta para ouvir/usar")
    parser.add_argument("--name", required=True, help="Seu nome de usuário (aparecerá nas mensagens)")
    parser.add_argument("--socks", help="(opcional) SOCKS5 proxy host:port — ex: 127.0.0.1:9050 (Tor)")
    args = parser.parse_args()

    socks_conf = None
    if args.socks:
        if not SOCKS_AVAILABLE:
            print("[!] pysocks não instalado — instalar 'pip install pysocks' para usar --socks")
            return
        try:
            hp = args.socks.split(":")
            socks_conf = (hp[0], int(hp[1]))
        except Exception:
            print("[!] Formato de --socks inválido. Use host:port")
            return

    # run chosen mode
    if args.listen:
        run_listen(args.host, args.port, args.name, socks_proxy=socks_conf)
    else:
        run_connect(args.host, args.port, args.name, socks_proxy=socks_conf)


if __name__ == "__main__":
    main()
