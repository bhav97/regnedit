#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" consumes dumps from the MCT android app, replaces registration number """

import argparse

def main(args):
    """ edits dumpfile """
    with args.dump as cereal:
        cereal.seek(0x00)
        zero = cereal.read(0x8e)
    if zero[0x0b:0x6d] == (0x6d-0x0b) * zero[0x0b]:
        print("sector is probably filled with 0, please check the dump")
    number = ''.join("{:x}".format(ord(c)) for c in args.regno)
    print(args.regno + " >> " + args.dump.name + " ==> " + args.output.name)
    with args.output as rice:
        rice.seek(0x00)
        rice.write(zero[0x00:0x3c]
                   + number[0x00:0x10]+ '\x0a'
                   + number[0x10:0x4f]
                   + zero[0x4f:0x8e]+'\x0a')
        print("Key A: " + zero[0x6e:0x7c] + '\x0a'
              + "AC: " + zero[0x7c:0x82] + '\x0a'
              + "Key B: " + zero[0x82:0xff])
        rice.truncate()
    print("Done!")


def _i():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", help="MCT dump file", type=argparse.FileType('r'))
    parser.add_argument("regno", help="Registration number to embed in dump")
    parser.add_argument("output", help="output dump file", type=argparse.FileType('w'))
    return parser.parse_args()

if __name__ == '__main__':
    main(_i())
