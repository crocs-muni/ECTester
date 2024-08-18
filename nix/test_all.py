#!/usr/bin/env python

import argparse
import json
import time

from pathlib import Path

import subprocess as sp


def base_options(library):
    match library:
        case "openssl" | "botan" | "boringssl" | "ippcp" | "libressl" | "gcrypt" | "nettle":
            return ["-ps", "123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234"]
        case "cryptopp" | "mbedtls":
            return ["-ps", "12345678"]
        case _:
            return []

def default_options(library):
    match library:
        case "botan" | "cryptopp":
            return ["-gt", "ECDH"]
        case _:
            return []

def test_vectors_options(library):
    return default_options(library)

def performance_options(library):
    return default_options(library)

def signature_options(library):
    match library:
        case "nettle" | "gcrypt" | "boringssl" | "openssl" | "tomcrypt" | "libressl" | "ippcp" | "mbedtls":
            return ["-st", "NONEwithECDSA"]
        case _:
            return []

def miscellaneous_options(library):
    return default_options(library)

def twist_options(library):
    return default_options(library)

def invalid_options(library):
    return default_options(library)

def degenerate_options(library):
    return default_options(library)

def cofactor_options(library):
    return default_options(library)

def composite_options(library):
    return default_options(library)

def edge_cases_options(library):
    return default_options(library)

def wrong_options(library):
    return default_options(library)

def build_library(library, version):
    command = ["nix", "build", f"?submodules=1#{library}.{version}"]
    result = sp.run(command, check=False)
    return result.returncode == 0

def test_library(library, test_suite, version):
    opts = base_options(library)
    opts.extend(globals()[f"{test_suite.replace('-', '_')}_options"](library))
    command = ["./result/bin/ECTesterStandalone", "test", f"-oyml:results/{library}_{test_suite}_{version}.yml", "-q", *opts, test_suite, library]
    print(" ".join(command))
    try:
        result = sp.run(command, timeout=60, check=False)
        print(f"{library} {test_suite} {version} = {result.returncode}")
    except sp.TimeoutExpired:
        print(f"{library} {test_suite} {version} timed-out!")
    

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--library")
    parser.add_argument("-s", "--suite")
    args = parser.parse_args()
    library = args.library
    suite = args.suite

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

    suites = [
        "default",
        "test-vectors",
        "performance",
        "signature",
        "miscellaneous",
        "invalid",
        "twist",
        "degenerate",
        "edge-cases",
        "cofactor",
        "composite",
        "wrong"
    ]


    if library is None:
        libraries2test = libraries
    else:
        libraries2test = [library]

    if suite is None:
        suites2test = suites
    else:
        suites2test = [suite]

    for library in libraries2test:
        with open(f"./nix/{library}_pkg_versions.json", "r") as f:
            versions = list(json.load(f).keys())
        for version in versions:
            built = build_library(library, version)
            for suite in suites2test:
                test_library(library, suite, version)


if __name__ == '__main__':
    main()
