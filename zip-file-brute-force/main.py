import string
import time
import pprint as pp
import zipfile


def iterative_pass_generator(length, charlist):
    passwords = []

    for current_length in range(length):
        single_letters = [letter for letter in charlist]
        for _ in range(current_length):
            single_letters = [letter + char for char in charlist for letter in single_letters]

        passwords += single_letters
    return passwords


def recursive_pass_generator(length, charlist):
    passwords = []
    recursive_core(charlist, '', length, len(charlist), passwords)
    return passwords


def recursive_core(charlist, prefix, length, charlist_size, passwords):
    if length == 0:
        return passwords.append(prefix)

    for i in range(charlist_size):
        new_prefix = prefix + charlist[i]
        recursive_core(charlist, new_prefix, length - 1, charlist_size, passwords)


def crack_password(length):
    """
    cracks the zip file by a brute force attack
    :param length: length of the password to be generated
    :return: None
    """

    charlist = [letter for letter in string.ascii_lowercase]
    # passwords = iterative_pass_generator(length, charlist)
    passwords = recursive_pass_generator(length, charlist)
    pp.pprint(len(passwords))
    z = zipfile.ZipFile('secret.zip')
    tries = 0

    for password in passwords:
        try:
            tries += 1
            z.setpassword(password.encode('ascii'))
            z.extract('secret.txt')
            pp.pprint(f'Pass found after {tries}. It is: {password}')
            break
        except:
            pass


if __name__ == '__main__':
    crack_password(int(input('Enter the length of the password to be generated: ')))
