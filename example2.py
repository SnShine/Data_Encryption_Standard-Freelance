import sys

class _base(object):
    def __init__(self):
        print("from base class init")


class des(_base):
    def __init__(self):
        print("init class of des class")

if __name__== "__main__":
    if len(sys.argv)!= 3:
        print("Error\nUsage:")