#!/usr/bin/env python

import argparse
import json

import subprocess as sp

def get_all_versions(library):
    with open(f"./nix/{library}_pkgs_versions.json", "r") as handle:
        versions = json.load(handle)

    return versions

def can_build(library, version):
    try:
        sp.check_output(["nix", "build", f"'.#shim.{library}.{version}'"])
    except sp.CalledProcessError as e:
        return False
    return True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--library")
    library = args.library

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
                print(lib)
                for version in get_all_versions(lib):
                    print(f"{version}: {can_build(lib, version)}")
        case _:
            print(lib)
            for version in get_all_versions(lib):
                print(f"{version}: {can_build(lib, version)}")


if __name__ == '__main__':
    main()
