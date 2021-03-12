from BitVector import *
import numpy as np
import pprint as pp
import math
import os
import time

AES_modulus = BitVector(bitstring='100011011')
Sbox = [i for i in range(256)]
InvSbox = [0 for _ in range(256)]


def sbox_converter(value):
    """
    converts a value to on SBOX element
    :param value: the value to be converted
    :return: the sbox element corresponding to the value
    """
    mi = BitVector(intVal=value, size=8).gf_MI(AES_modulus, 8)
    const = BitVector(hexstring='63')
    si = mi.intValue() ^ (mi << 1).intValue() ^ (mi << 1).intValue() ^ (mi << 1).intValue() ^ (
            mi << 1).intValue() ^ const.intValue()
    return BitVector(intVal=si, size=8)


Sbox = [sbox_converter(elem) for elem in Sbox[1:]]
Sbox.insert(0, BitVector(hexstring='63'))


def inverse_sbox_converter(index):
    """
     converts a value to on inverse SBOX element
    :param index: the index to be converted to an inverse SBOX element
    :return: the updated inverse sbox element in the inverse SBOX
    """
    bv = Sbox[index]
    InvSbox[bv.intValue()] = BitVector(intVal=index, size=8)


for index, elem in enumerate(Sbox):
    inverse_sbox_converter(index)

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]


class KeyHandler:
    """
    Used for handling the rounding-constant generation and required key generation.
    Formats the key as needed.
    """

    def __init__(self, utility, key):
        """
        Constructor for KeyHandler.
        :param utility: Utility object for necessary function calls.
        :param key: Initial Unformed key
        """
        self.utils = utility
        self.key = key
        self.generated_keys = []

    def format_key_input(self):
        """
        Formats the key if it is greater than 16 chars long
        :return: Formatted key
        """
        str_len = len(self.key)
        if str_len < 16:
            self.key = self.key.ljust(16, '0')
        elif str_len > 16:
            self.key = self.key[:16]
        print(self.key)
        return self.key

    def schedule_keys(self):
        """
        Schedules the keys and returns the updated key list
        :return: None
        """
        # storing the key as a bitvector in the first array
        self.generated_keys.append(BitVector(textstring=self.key))
        prev_rc = BitVector(hexstring='01')

        for round in range(1, 11):

            current_key = self.generated_keys[len(self.generated_keys) - 1].get_text_from_bitvector()
            w = [
                BitVector(textstring=current_key[:4]),
                BitVector(textstring=current_key[4:8]),
                BitVector(textstring=current_key[8:12]),
                BitVector(textstring=current_key[12:16])
            ]

            # print(BitVector(textstring=w3).getHexStringFromBitVector())
            modified_word, next_rc = self.g(w[3], prev_rc, round)
            prev_rc = BitVector(textstring=next_rc.get_text_from_bitvector()[:1])
            # self.utils.print_bitvector(prev_rc, format="hex")
            # self.utils.print_bitvector(prev_rc, 'hex')

            # first word of next key
            w[0] = w[0] ^ modified_word

            # then find the consecutive words
            for i in range(1, 4):
                # # print('before w[i] = ', end='')
                # self.utils.print_bitvector(w[i], 'hex')
                # # print('before w[i-1] = ', end='')
                # self.utils.print_bitvector(w[i - 1], 'hex')

                w[i] = w[i - 1] ^ w[i]

            s = ''.join(bv.get_text_from_bitvector() for bv in w)

            self.generated_keys.append(BitVector(textstring=s))

    def g(self, word, prev_rc, round):
        """
        G function for fourth word generation in every round
        :param word: Word to be modified
        :param prev_rc: Previous rounding constant for byte substitution
        :param round: Round for which the rc is to be generated
        :return: Modified word with rc and the rc for the next round
        """
        # print(word.get_hex_string_from_bitvector())
        word = word.deep_copy()

        # circular left shift the byte
        word = word << 8

        # byte substitution
        word = self.utils.substitute(word.get_text_from_bitvector())

        rc_list = self.utils.generate_rounding_const(
            prev_rc,
            round
        )
        # self.utils.print_bitvector(prev_rc, format="hex")
        # print(len(rc_list[0]))
        s = ''.join(bv.get_text_from_bitvector() for bv in rc_list)
        rc = BitVector(textstring=s)
        # self.utils.print_bitvector(rc, format="hex")
        return word ^ rc, rc

    def print_keys(self):
        """
        Prints the keys
        :return: None
        """
        for key in self.generated_keys:
            hex_format = key.get_hex_string_from_bitvector()
            for i in range(0, len(hex_format), 2):
                print(hex_format[i:i + 2], end=' ')
            print()


class Utility:

    @staticmethod
    def substitute(word):
        """
        For Substitution in G function
        :param word: word to be substituted
        :return: substituted word
        """
        result = ''
        for i in range(4):
            temp = BitVector(textstring=word[i])
            int_val = temp.intValue()
            s_val = Sbox[int_val]
            result += s_val.get_text_from_bitvector()
        return BitVector(textstring=result)

    def generate_rounding_const(self, prev_rc, round):
        """
        Generate rouding constant for a particular round
        :param prev_rc: Previous rounding constant
        :param round: The round
        :return:
        """
        # self.print_bitvector(prev_rc, format="hex")
        hex_80 = BitVector(hexstring='80')
        rc2 = BitVector(hexstring='00')
        rc3 = BitVector(hexstring='00')
        rc4 = BitVector(hexstring='00')
        multiplier = BitVector(hexstring="02")
        rounding_constants = [rc2, rc3, rc4]

        if round > 1 and prev_rc <= hex_80:
            rounding_constants.insert(0, self.gf_multiply(prev_rc, multiplier))
        else:
            rounding_constants.insert(0, prev_rc)

        return rounding_constants

    @staticmethod
    def gf_multiply(bv1, bv2):
        """
        Multiplies to bitvector by Galois Field
        :param bv1: One Bitvector
        :param bv2: One Bitvector
        :return:
        """
        AES_modulus = BitVector(bitstring='100011011')
        return bv1.gf_multiply_modular(bv2, AES_modulus, 8)

    @staticmethod
    def print_bitvector(bitvector, format):
        """
        Prints Bitvectorto the screen
        :param bitvector: Bitvector to be printed
        :param format: The format to be printed
        :return:
        """
        if format == 'string':
            print(f'{bitvector.get_text_from_bitvector()} [In STRING]')
        elif format == 'hex':
            print(f'{bitvector.get_hex_string_from_bitvector()} [In HEX]')
        elif format == 'ASCII':
            print(f'{bitvector.get_bitvector_in_ascii()} [In ASCII]')
        print()

    @staticmethod
    def format_to_matrix(hex_string='5468617473206d79204b756e67204675'):
        """
        Formats a hex string to a 4 * 4 matrix by default
        :param hex_string: The string to be formatted
        :return: matrix representation of the string.
        """
        matrix = []
        for i in range(0, len(hex_string), 2):
            matrix.append(hex_string[i:i + 2])
        # print(len(matrix))
        matrix = np.transpose(np.array([matrix]).reshape(4, 4)).tolist()
        matrix = [[BitVector(hexstring=element) for element in row] for row in matrix]
        return matrix

    @staticmethod
    def byte_substitution(matrix_entry, inverse=False):
        """
        The matrix entry for byte substitution
        :param matrix_entry: Matrix entry to be substituted
        :param inverse: Controlling parameter to choose SBox or InvSBox
        :return: Substituted Value
        """
        matrix_entry = matrix_entry.deep_copy()
        int_val = matrix_entry.intValue()
        if inverse:
            return InvSbox[int_val]
        return Sbox[int_val]

    @staticmethod
    def print_matrix(matrix):
        """
        Printing the matrix
        :param matrix: Matrix to be printed
        :return: None
        """
        pp.pprint([[elem.get_hex_string_from_bitvector() for elem in row] for row in matrix])

    def multiply_matrix(self, matrix, row, col, inverse):
        """
        Multiplies the current state matrix with the InvMixer and Mixer as required.
        :param matrix: The matrix to be multiplied
        :param row: The rows of the matrix
        :param col: The columns of the matrix
        :param inverse: Controlling parameter to choose Mixer or Inverse Mixer
        :return: Result of matrix multiplication
        """
        if inverse:
            mixer_matrix = InvMixer
        else:
            mixer_matrix = Mixer
        result = [[BitVector(hexstring='00') for _ in range(col)] for _ in range(row)]
        # self.print_matrix(result)

        for i in range(row):
            for j in range(col):
                for k in range(row):
                    entry = self.gf_multiply(mixer_matrix[i][k], matrix[k][j])
                    temp = BitVector(hexstring=result[i][j].get_hex_string_from_bitvector()) ^ entry
                    result[i][j] = temp

        # self.print_matrix(result)
        return result

    @staticmethod
    def row_shift(single_row, row, is_left):
        """
        For cyclic row shifting of by amount=row left or right
        :param single_row: Row to be shifted
        :param row: The amount to be shifted
        :param is_left: Left shift or right shift
        :return: Shifted row
        """
        hex_representation = [elem.get_hex_string_from_bitvector() for elem in single_row]

        if is_left:
            row = -row

        rolled = np.roll(np.array(hex_representation), row).tolist()
        bit_vector = [BitVector(hexstring=string) for string in rolled]
        return bit_vector

    @staticmethod
    def format_input(inp, input_type='utf-8'):
        """
        Formatting input based on type
        :param inp: Input to be formatted
        :param input_type: Type of the input
        :return: Formatted Input
        """
        original_length = len(inp)
        # print(original_length)

        if original_length % 16 != 0:
            nearest_multiple = 16 * math.ceil(original_length / 16)
            if input_type == 'utf-8':
                return inp.ljust(nearest_multiple, ' '), nearest_multiple - original_length
            else:
                return inp.ljust(nearest_multiple, '0'), nearest_multiple - original_length

        return inp, 0

    @staticmethod
    def format_long_inputs(input, chunk_size):
        """
        Used for formatting long inputs to chunks of 16/32
        :param input: Input to be formatted
        :param chunk_size: Size of the chunk to be formatted to
        :return: Generator generating the input to be formatted
        """
        length = len(input)
        size = chunk_size
        for i in range(0, length, size):
            yield input[i:i + size]

    @staticmethod
    def read_file(file_name):
        """
        Reads a file and returns required data
        :param file_name: The name of the file to be read
        :return: Data(text/hex), type, file pointer and extension of the file
        """
        file = open(file_name, 'rb')
        file_ext = os.path.splitext(file_name)[1]
        file_pointer = file.read()
        try:
            text_data = file_pointer.decode('utf-8')
            return text_data, 'utf-8', file_pointer, file_ext
        except:
            hex_data = file_pointer.hex()
            return hex_data, 'bin', file_pointer, file_ext


class AES:
    def __init__(self, keys, state_matrix, utils):
        """
        constructor for encryption class
        :param keys: list of keys in form of BitVector
        :param state_matrix: the state matrix in hex_string
        :param utils: utility object
        """
        self.round_keys = keys
        self.current_state_matrix = state_matrix
        self.utils = utils

    def add_round_key(self, state_matrix, inverse=False, round=0):
        """
        Adds rounding key to the state matrix to modify it
        :param state_matrix: State matrix to be formatted
        :param inverse: whether this is encrypt or decrypt
        :param round: Round of the encryption or decryption
        :return: Changed State after adding rounding constant
        """
        round_key = u.format_to_matrix(self.round_keys[round].get_hex_string_from_bitvector())
        if (round == 0 and not inverse) or (inverse and round == 10):
            # print(round)
            state_matrix = u.format_to_matrix(state_matrix)

        # pp.pprint([[elem.get_hex_string_from_bitvector() for elem in row] for row in round_key])
        # pp.pprint([[elem.get_hex_string_from_bitvector() for elem in row] for row in state_matrix])

        # Element wise XOR
        result = [[state_matrix[row][col] ^ round_key[row][col]
                   for col in range(len(state_matrix))]
                  for row in range(len(state_matrix))]

        self.current_state_matrix = result

        # pp.pprint([[elem.get_hex_string_from_bitvector() for elem in row] for row in result])

    def matrix_byte_substitution(self, inverse):
        """
        Performs Byte Substitution of the whole matrix
        :param inverse: Controlling parameter to choose sbox or Invsbox
        :return: Byte Substituted state matrix
        """
        for row in range(len(self.current_state_matrix)):
            for col in range(len(self.current_state_matrix)):
                self.current_state_matrix[row][col] = self.utils.byte_substitution(self.current_state_matrix[row][col],
                                                                                   inverse=inverse)

        # self.utils.print_matrix(self.current_state_matrix)

    def shift_rows(self, is_left=True):
        """
        Row shifting for the state matrix by row order
        :param is_left: Controlling parameter to choose whether to left shift or right shift
        :return: Row Shifted State Matrix
        """
        for row_no, current_row in enumerate(self.current_state_matrix):
            self.current_state_matrix[row_no] = self.utils.row_shift(current_row, row_no, is_left)

        # self.utils.print_matrix(self.current_state_matrix)

    def mix_columns(self, inverse=False):
        """
        Matrix mixing operation upon current state matrix
        :param inverse: Controlling parameter to choose Mixer or Inverse Mixer
        :return: Mixed State Matrix
        """
        mat_len = 4
        self.current_state_matrix = self.utils.multiply_matrix(self.current_state_matrix, mat_len, mat_len, inverse)

    def encrypt(self):
        """
        Encrypts the modified current state matrix through a series of steps as below:
        1. Adds Round key to the current state matrix
        2. Perform the following sub-steps for 9 consecutive round:
            1. Matrix Byte substitution with SBox
            2. Shift rows by row number and to the left of the state matrix
            3. Mix Columns of the state matrix with the Mixer Matrix
            4. Add Round key of the round i.
        3. Perform the following sub-steps for a single round:
            1. Matrix Byte Substitution with SBox
            2. Shift rows by row number and to the left of the state matrix
            3. Adds Round key to the current state matrix
        :return: None
        """
        self.add_round_key(encrypt.current_state_matrix)

        for i in range(1, 10):
            self.matrix_byte_substitution(inverse=False)
            self.shift_rows()
            # print(f'mix columns after round {i}')
            self.mix_columns()
            # u.print_matrix(encrypt.current_state_matrix)
            self.add_round_key(encrypt.current_state_matrix, round=i)
            # print(f'after round {i}')
            # u.print_matrix(encrypt.current_state_matrix)

        self.matrix_byte_substitution(inverse=False)
        self.shift_rows()
        self.add_round_key(encrypt.current_state_matrix, round=10)

    def get_hidden_text(self):
        """
        Used to obtain textual representation from current state matrix
        :return: hex string, hex matrix, text string and ascii text from the state matrix
        """
        hex_matrix = [[elem.get_hex_string_from_bitvector() for elem in row] for row in self.current_state_matrix]
        n = np.transpose(np.array(hex_matrix))
        cipher_hex_string = ''.join(elem for elem in n.reshape(16))
        bv = BitVector(hexstring=cipher_hex_string)
        text_string = bv.get_text_from_bitvector()
        ascii_text = bv.get_bitvector_in_ascii()
        return cipher_hex_string, hex_matrix, text_string, ascii_text

    def decrypt(self):
        """
        Encrypts the modified current state matrix through a series of steps as below:
        1. Adds Round key to the current state matrix
        2. Perform the following sub-steps for 9 consecutive round:
            1. Shift rows by row number and to the right of the state matrix
            2. Matrix Byte substitution with InvSBox
            3. Add Round key of the round i.
            4. Mix Columns of the state matrix with the Mixer Matrix

        3. Perform the following sub-steps for a single round:
            1. Shift rows by row number and to the right of the state matrix
            2. Matrix Byte Substitution with InvSBox
            3. Adds Round key to the current state matrix
        :return: Deciphered text, hex representation and ascii value
        """
        cipher_hex_string, _, _, _ = self.get_hidden_text()
        # round 0
        self.add_round_key(cipher_hex_string, inverse=True, round=10)
        # u.print_matrix(self.current_state_matrix)

        for i in range(1, 10):
            self.shift_rows(is_left=False)
            self.matrix_byte_substitution(inverse=True)
            # print(f'mix columns after round {i}')
            self.add_round_key(encrypt.current_state_matrix, round=10 - i)
            self.mix_columns(inverse=True)
            # u.print_matrix(self.current_state_matrix)
            # print(f'after round {i}')
            # u.print_matrix(encrypt.current_state_matrix)

        self.shift_rows(is_left=False)
        self.matrix_byte_substitution(inverse=True)
        self.add_round_key(encrypt.current_state_matrix, inverse=True, round=0)

        deciphered_hex, hex_matrix, deciphered, ascii = self.get_hidden_text()
        # print(deciphered)
        return deciphered, deciphered_hex, ascii


if __name__ == '__main__':

    total_encrypt_time_elapsed = 0
    total_decrypt_time_elapsed = 0
    deciphered = ''
    deciphered_hex = ''
    ciphered = ''
    ciphered_hex = ''

    u = Utility()

    key, _, _, _ = u.read_file(input('Enter the key containing file: '))

    keyHandler = KeyHandler(Utility(), key)
    key = keyHandler.format_key_input()
    print('Key:')
    print(f'{key} [In ASCII]')
    u.print_bitvector(BitVector(textstring=key), format="hex")

    # Scheduling keys
    start_time_key_scheduling = time.time()
    keyHandler.schedule_keys()
    key_scheduling_time_elapsed = time.time() - start_time_key_scheduling
    generated_keys = keyHandler.generated_keys

    # reading file
    data, type, file_pointer, ext = u.read_file(input('Please Give File Name to encrypt-decrypt: '))

    if type == 'utf-8':
        print(f'Plain Text:')
        print(f'{data} [In ASCII]')
        u.print_bitvector(BitVector(textstring=data), format="hex")
    inp, extra_char_len = u.format_input(data, type)  # padding to a multiples of 16 for both text and binary

    # performing encryption and decryption for various file formats
    if type == 'utf-8':
        for text in u.format_long_inputs(inp, 16):
            text = BitVector(textstring=text)
            encrypt = AES(
                generated_keys,
                text.get_hex_string_from_bitvector(),
                u
            )
            start_time = time.time()
            encrypt.encrypt()
            cipher_hex_string, _, _, ascii_text = encrypt.get_hidden_text()

            # concatenating the ciphered strings
            ciphered_hex += cipher_hex_string
            ciphered += ascii_text

            total_encrypt_time_elapsed += time.time() - start_time

            start_time_decrypt = time.time()
            _, dec_hex, ascii_deciphered = encrypt.decrypt()
            total_decrypt_time_elapsed += time.time() - start_time_decrypt

            # concatenating the deciphered strings
            deciphered += ascii_deciphered
            deciphered_hex += dec_hex
    else:
        for text in u.format_long_inputs(inp, 32):
            text = BitVector(hexstring=text)
            encrypt = AES(
                generated_keys,
                text.get_hex_string_from_bitvector(),
                u
            )
            start_time = time.time()
            encrypt.encrypt()
            total_encrypt_time_elapsed += time.time() - start_time

            start_time_decrypt = time.time()
            _, dec_hex, _ = encrypt.decrypt()
            total_decrypt_time_elapsed += time.time() - start_time_decrypt
            deciphered += dec_hex

    # print(f'length after adding characters: {len(inp)}')
    # print(f'decoded char length before cutting: {len(deciphered)}')
    # # deciphered = deciphered[:len(deciphered) - extra_char_len]
    # deciphered = deciphered[:len(deciphered) - extra_char_len]
    # print(f'input character length: {len(data)}')
    # print(f'decoded char length: {len(deciphered)}')
    # print(len(data) == len(deciphered))

    # Printing required materials
    if type != 'utf-8':
        data = file_pointer.fromhex(deciphered)
        f = open(f'result{ext}', 'wb')
        f.write(data)
    else:
        print('Cipher Text: ')
        print(f'{ciphered_hex} [In HEX]')
        print(f'{ciphered} [In ASCII]')
        print()

        print('Deciphered Text: ')
        print(f'{deciphered_hex} [In HEX]')
        print(f'{deciphered} [In ASCII]')
        print()

    # printing required statistics
    print('Execution Time')
    print(f'Key Scheduling: {key_scheduling_time_elapsed}')
    print(f'Encryption Time: {total_encrypt_time_elapsed}')
    print(f'Decryption Time: {total_decrypt_time_elapsed}')
