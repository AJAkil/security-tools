from BitVector import *
import pprint as pp

SBox = [i for i in range(256)]
InvSBox = [0 for _ in range(256)]

AES_modulus = BitVector(bitstring='100011011')


def sbox_converter(value):
    mi = BitVector(intVal=value, size=8).gf_MI(AES_modulus, 8)
    const = BitVector(hexstring='63')
    si = mi.intValue() ^ (mi << 1).intValue() ^ (mi << 1).intValue() ^ (mi << 1).intValue() ^ (
            mi << 1).intValue() ^ const.intValue()
    return BitVector(intVal=si, size=8)


SBox = [sbox_converter(elem) for elem in SBox[1:]]
SBox.insert(0, BitVector(hexstring='63'))

print(len(SBox))
b = BitVector(hexstring="71")
int_val = b.intValue()
s = SBox[int_val]
print('hello hello hello', s.get_bitvector_in_hex())


# pp.pprint([elem.get_hex_string_from_bitvector() for elem in SBox])

def inverse_sbox_converter(index):
    bv = SBox[index]
    InvSBox[bv.intValue()] = BitVector(intVal=index, size=8)


for index, elem in enumerate(SBox):
    inverse_sbox_converter(index)

pp.pprint([elem.get_hex_string_from_bitvector() for elem in InvSBox])


