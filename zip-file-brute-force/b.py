# Python 3 program to print all

import string
import time
g =[]
# possible strings of length k

# The method that prints all
# possible strings of length k.
# It is mainly a wrapper over
# recursive function printAllKLengthRec()
def printAllKLength(set, k):
    n = len(set)
    printAllKLengthRec(set, "", n, k)


# The main recursive method
# to print all possible
# strings of length k
def printAllKLengthRec(set, prefix, n, k):
    # Base case: k is 0,
    # print prefix
    if (k == 0):
        print('adding ',prefix)
        g.append(prefix)
        return

    # One by one add all characters
    # from set and recursively
    # call for k equals to k-1
    for i in range(n):
        # Next character of input added
        newPrefix = prefix + set[i]

        # k is decreased, because
        # we have added a new character
        printAllKLengthRec(set, newPrefix, n, k - 1)

    # Driver Code


if __name__ == "__main__":
    print("First Test")
    set1 = [letter for letter in string.ascii_lowercase]
    k = 3
    start_time = time.time()
    printAllKLength(set1, k)
    end_time = time.time()
    print(f'Time Taken: {end_time - start_time}')
    print(len(g))
