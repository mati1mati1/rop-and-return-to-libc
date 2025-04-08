import struct


def address_to_bytes(address: int) -> bytes:
    """Convert an address to bytes, in little endian."""
    return struct.pack('<L', address)


########### QUESTION 1 ##############

# Memory address of "/bin/sh" in `libc`.
# USE THIS IN `q1b.py` AND `q1c.py`.
LIBC_BIN_SH = 0xb7c96338

# Memory address of the `system` function. This function is not in the PLT of
# the program, so you will have to find it's address in libc. Use GDB :)
# USE THIS IN `q1c.py`.
SYSTEM = 0xb7b4f040

# Memory address of the `exit` function. This function is also not in the PLT,
# you'll need to find it's address in libc.
# USE THIS IN `q1c.py`.
EXIT = 0xb7b41990

########### QUESTION 2 ##############

# Memory address of the start of the `.text` section of `libc`.
# The code in q2.py will automatically use this.
LIBC_TEXT_START = 0xb7b270f0

########### QUESTION 3 ##############

# Memory address of the `auth` variable in the sudo program.
# USE THIS IN `q3.py`.
AUTH = 0x804a054

########### QUESTION 4 ##############

# Memory address of the `puts` function. You can find the address of this
# function either in the PLT or in libc.
# USE THIS IN `q4.py`.
PUTS = 0xb7b7a460
