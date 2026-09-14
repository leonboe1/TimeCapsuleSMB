"""Compile the actual patched sshpass parser with ASan/UBSan and simulated reads.

No SSH connection, user password, or downloaded executable is used by this test.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import tempfile


def check(source: Path) -> None:
    text = source.read_text()
    start = text.index("int handleoutput( int fd )\n{")
    end = text.index("\nvoid write_pass_fd(", start)
    functions = text[start:end]  # Real handleoutput() and match(), not copies.
    harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define PASSWORD_PROMPT "assword:"
enum { RETURN_RUNTIME_ERROR=3, RETURN_INCORRECT_PASSWORD=5,
       RETURN_HOST_KEY_UNKNOWN=6, RETURN_HOST_KEY_CHANGED=7 };
struct { const char *pwprompt; int verbose; } args;
static const char *input;
static ssize_t length;
static int read_errno, password_writes;
static ssize_t fake_read(int fd, void *buffer, size_t capacity) {
    if (length > 0) { assert((size_t)length <= capacity); memcpy(buffer, input, length); }
    errno = read_errno;
    return length;
}
#define read fake_read
static void write_pass(int fd) { ++password_writes; }
int match(const char *, const char *, ssize_t, int);
'''
    main = r'''
int main(int argc, char **argv) {
    assert(argc == 2);
    int mode = atoi(argv[1]);
    if (mode < 4) {
        int errors[] = { EAGAIN, EINTR, EIO, 0 };
        length = mode == 3 ? 0 : -1;
        read_errno = errors[mode];
        int expected = mode < 2 ? 0 : mode == 2 ? RETURN_RUNTIME_ERROR : -1;
        assert(handleoutput(-1) == expected);
        assert(password_writes == 0);
    } else if (mode == 4) {
        input = "Pass"; length = 4;
        assert(handleoutput(-1) == 0 && password_writes == 0);
        input = "word:"; length = 5;
        assert(handleoutput(-1) == 0 && password_writes == 1);
        input = "Password:"; length = 9;
        assert(handleoutput(-1) == RETURN_INCORRECT_PASSWORD && password_writes == 1);
    } else {
        char maximum[255]; memset(maximum, 'x', sizeof(maximum));
        input = maximum; length = sizeof(maximum);
        assert(handleoutput(-1) == 0 && password_writes == 0);
        input = "The authenticity of host "; length = strlen(input);
        assert(handleoutput(-1) == RETURN_HOST_KEY_UNKNOWN && password_writes == 0);
    }
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="sshpass-regression-") as directory:
        root = Path(directory)
        cfile, executable = root / "parser.c", root / "parser"
        cfile.write_text(harness + functions + main)
        subprocess.run(["clang", "-g", "-O1", "-fsanitize=address,undefined",
                        "-fno-sanitize-recover=all", str(cfile), "-o", str(executable)], check=True)
        for case in range(6):
            subprocess.run([str(executable), str(case)], check=True, timeout=10)
    print("sshpass parser: six sanitizer cases passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    check(parser.parse_args().source)
