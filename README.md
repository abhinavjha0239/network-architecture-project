# BHP/1: HTTP, in binary

A small binary protocol with HTTP's request/response semantics, a file server that speaks it, and a client that speaks it.

| Hand-in item | File |
|---|---|
| 1. The spec | [SPEC.md](SPEC.md), printed as [SPEC.pdf](SPEC.pdf) (two pages) |
| 2. The programs | [bserve.c](bserve.c) (track 1, server) and [bcurl.c](bcurl.c) (track 2, client) |
| 3. Annotated hexdump | [HEXDUMP.md](HEXDUMP.md) |

The two programs share no code. Each is one self-contained C file written against the spec, so either can be handed in or swapped for a partner's on its own.

## Build

Needs a C compiler and nothing else.

```
make                 # Linux, macOS
mingw32-make         # Windows with MinGW-w64
```

Or without make:

```
gcc -O2 -o bserve bserve.c -pthread                  # Linux, macOS
gcc -O2 -o bcurl  bcurl.c

gcc -O2 -o bserve.exe bserve.c -lws2_32              # Windows
gcc -O2 -o bcurl.exe  bcurl.c  -lws2_32
```

## Run

```
./bserve ./www 9000
./bcurl -v localhost:9000/index.html
```

**bserve** `[-v] [-b ADDR] ROOT PORT` serves the files under ROOT. It logs one line per request to stderr; `-v` adds a hexdump of every frame. By default it listens on all interfaces, so the first run on Windows brings up a firewall prompt. `-b 127.0.0.1` keeps it to this machine.

**bcurl** `[-v] [-I] [-o FILE] HOST:PORT/PATH [/PATH ...]` writes the body to stdout.

- `-v` hexdumps every frame, sent and received, to stderr.
- `-I` sends HEAD and prints the response fields.
- `-o FILE` writes to a file. Use it for binary files in Windows PowerShell 5, whose `>` re-encodes output as text.
- Several paths are all fetched over one connection, with the bodies written in the order given: `./bcurl localhost:9000/a.html /b.html /c.html`. A URL on a different host is refused, because it would need a second connection.
- Exit status: `0` success, `4` a response was 4xx, `5` a response was 5xx, `1` network or protocol failure, `2` usage.

In Git Bash, a bare `/path` argument is rewritten into a Windows path before bcurl sees it. Write the full `localhost:9000/path` there, or set `MSYS_NO_PATHCONV=1`.

## Test

```
make test            # or: python tests/interop.py
```

[tests/interop.py](tests/interop.py) is a third implementation of the protocol, written from the spec in Python and sharing nothing with the C programs. It plays client against `bserve` and server against `bcurl`, and as a server it does what another implementation is allowed to do and `bserve` never does: frame types from a future version, interleaved streams, responses finishing out of order, frames arriving one byte at a time. Pass a name to run a subset: `python tests/interop.py client_`.

## Limits

- GET and HEAD only. There are no request bodies in version 1.
- `bserve` uses one thread per connection and has no idle timeout, so it is not hardened against a client that connects and goes silent.
- `bserve` answers the requests on a connection one at a time, in order. The protocol allows interleaving, and `bcurl` handles it, but this server does not produce it.
- `bserve` will not serve a path with a segment that starts with a dot. That is how `..` is refused; it also hides dotfiles.
