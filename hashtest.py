from binascii import unhexlify, hexlify
from job import *
from midstate import *

version = "20000000"
prev_hash = "252d1a5392e88f0cf995319d0e77fb5be2bff3d9000918c80000000000000000"
merkle = "31eefd45ac9fb7eab6367f88afb9ca6cdc9180752295a910c8460aeab1d606c7"
ntime = "62d08b61"
nbits = "1709a7af"
padding = "000000000000008000000000000000000000000000000000000000000000000000000000"

full_header = "20000000252d1a5392e88f0cf995319d0e77fb5be2bff3d9000918c8000000000000000031eefd45ac9fb7eab6367f88afb9ca6cdc9180752295a910c8460aeab1d606c762d08b611709a7af000000000000008000000000000000000000000000000000000000000000000000000000"

result_midstate = "86:7F:60:D4:39:39:C8:D2:7F:93:36:7C:98:51:FC:3E:AF:71:71:63:84:45:26:ED:97:C2:2E:99:6F:46:DD:9F"


def hex2bin(hex_string):
    if hex_string[2] == ":":
        hex_string = hex_string.replace(":", "")
    return unhexlify(hex_string)


def single_hash(message):
    return hashlib.sha256(message).digest()


def reverse(lst):
    return bytes([ele for ele in reversed(lst)])


# stratum header
# stratum_header = hex2bin(version) + hex2bin(prev_hash) + hex2bin(merkle) + hex2bin(ntime) + hex2bin(nbits) + hex2bin(padding)
stratum_header = hex2bin(full_header)
print("stratum header: ", end='')
pretty_hex2(stratum_header)

# flip the first 64 bytes of data
# pretty_hex(stratum_header[:64])
# midstate_data = swap_endian_words(hexlify(stratum_header[:64]))
midstate_data = stratum_header[:64]

calc_midstate = calculateMidstate(midstate_data)
print("calc midstate: ", end='')
pretty_hex(reverse(calc_midstate))


print("Expected result: ", end='')
pretty_hex(hex2bin(result_midstate))
