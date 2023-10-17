#!/usr/bin/env python3
from pwn import *

# Reference
# https://github.com/Gallopsled/pwntools
# https://qiita.com/8ayac/items/12a3523394080e56ad5a
def send_payload(payload):
    log.info("payload : %s" % repr(payload))
    p.send(payload)
    return

def sendline_payload(payload):
    log.info("payload : %s" % repr(payload))
    p.sendline(payload)
    return

def print_address(symbols, address):
    log.info(symbols + ' : ' + hex(address))
    return

context.log_level = "info"
# context.log_level = "debug"

context.terminal = ["alacrity", "-e", "zsh", "-c"]

# binary = "./binary"
# elf = ELF(binary)
# context.binary = binary

# context(arch="i386", os="linux")
context(arch="amd64", os="linux")

ssh_host = "127.0.0.1"
ssh_user = "root"
ssh_password = "toor"
ssh_port = 22

ssh = ssh(host=ssh_host, user=ssh_user, password=ssh_password, port=ssh_port)

# ssh.upload("file", "/home/user/file")

p = ssh.process("./binary")

# exploit
buf = b"A" * 0x20

p.sendline_payload(buf)

sleep(1)

p.interactive()
