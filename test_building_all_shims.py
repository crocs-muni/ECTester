#!/usr/bin/env python

import argparse
import json
import time

import subprocess as sp

def get_all_versions(library):
    with open(f"./nix/{library}_pkg_versions.json", "r") as handle:
        versions = json.load(handle)

    return versions

def can_build(library, version, variant):
    cmd = ["nix", "build", f".#{variant}.{library}.{version}"]
    start = time.time()
    try:
        sp.check_output(cmd, stderr=sp.STDOUT)
    except sp.CalledProcessError as e:
        print(e.output.decode())
        return False, time.time() - start
    return True, time.time() - start

def valid_build_type(value):
    value = value.strip()
    valid_types = ["shim", "lib"]
    if value not in valid_types:
        raise argparse.ArgumentTypeError(f"'{value}' not from expected {', '.join(valid_types)})")
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--library")
    parser.add_argument("-d", "--variant", default="shim", type=valid_build_type)
    args = parser.parse_args()
    library = args.library
    variant = args.variant


    libraries = [
         "botan", 
         "cryptopp", 
         "openssl", 
         "boringssl", 
         "gcrypt", 
         "mbedtls", 
         "ippcp", 
         "nettle", 
         "libressl", 
    ]

    match library:
        case None:
            for lib in libraries:
                print(f"Library: {lib}")
                for version in get_all_versions(lib):
                    print(f"{version}: {can_build(lib, version, variant)}")
        case _:
            print(f"Library: {library}")
            for version in get_all_versions(library):
                print(f"{version}: {can_build(library, version, variant)}")


if __name__ == '__main__':
    main()
