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

def recv_loginfo():
	recv = p.recv()
	log.info("recv : %s" % repr(recv))
	return
def recvline_loginfo():
	recvline = p.recvline()
	log.info("recvline : %s" % repr(recvline))
	return

def print_address(s, addr):
	log.info(s + ' : ' + hex(addr))
	return

binary = "./"
host ="exploit.example.com"
port = 31337
libc = "./"

elf = ELF(binary)
context.binary = binary
context.log_level = "debug"

commands = """
continue
"""

# gdb.attach(s, "".join(f"break {bp}\n" for bp in breakpoints) + commands)

if len(sys.argv) >= 2 and sys.argv[1] == "r":
	# remote
	s = remote(host, port)
	libc = ELF(libc)
elif len(sys.argv) >= 2 and sys.argv[1] == "d":
	# debug
	s = gdb.debug(binary, commands, env={"LD_PRELOAD": libc})
	# libc = elf.libc
	libc = ELF(libc)
else:
	# local
	s = process(binary,env={"LD_PRELOAD": libc})
	# libc = elf.libc
	libc = ELF(libc)

shellcode = asm(shellcraft.sh())
str_bin_sh = "/bin/sh\x00"
str_bin = "/bin"
str_sh = "/sh\x00"
nop = "\x90"

# ELF

# addr_plt_read = elf.plt["read"]
# addr_got_read = elf.got["read"]
# addr_plt_write = elf.plt["write"]
# addr_got_write = elf.got["write"]
# addr_plt_printf = elf.plt["printf"]
# addr_got_printf = elf.got["printf"]
# addr_plt_puts = elf.plt["puts"]
# addr_got_puts = elf.got["puts"]
# addr_plt_fgets = elf.plt["fgets"]
# addr_got_fgets = elf.got["fgets"]
# addr_plt_system = elf.plt["system"]
# addr_symbols_main = elf.symbols["main"]

# libc

# libc_offset_system = libc.symbols["system"]
# libc_offset_printf = libc.symbols["printf"]
# libc_addr_plt_fgets = libc.plt["fgets"]
# libc_offset_open = libc.symbols["open"]
# libc_offset_read = libc.symbols["read"]
# libc_offset_write = libc.symbols["write"]
# libc_offset_mmap = libc.symbols["mmap"]
# libc_offset_exit = libc.symbols["exit"]
# libc_offset_execve = libc.symbols["execve"]
# libc_offset_str_bin_sh = next(libc.search(b"/bin/sh\x00"))

"""
Gadget
rp --file=binary --unique --rop=5

# elf

ret = next(elf.search(asm("ret")))
pop_rdi = next(elf.search(asm("pop rdi; ret")))
pop_rsi_r15 = next(elf.search(asm("pop rsi ; pop r15 ; ret")))
pop_rdx_r13 = next(elf.search(asm("pop rdx ; pop r13 ; ret")))
pop_rax = next(elf.search(asm("pop rax; ret")))
syscall = next(elf.search(asm("syscall; ret")))

# libc

libc_offset_binsh = next(libc.search(b"/bin/sh\x00"))
libc_offset_ret = next(libc.search(asm("ret")))
libc_offset_pop_rdi = next(libc.search(asm("pop rdi; ret")))
libc_offset_pop_rdx_rdi = next(libc.search(asm("pop rdx ; pop rsi ; ret")))
"""

payload = b""

s.sendline(payload)

sleep(1)
s.interactive()