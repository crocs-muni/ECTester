#!/usr/bin/env python

import argparse
import json
import time

from pathlib import Path

import subprocess as sp

def get_all_versions(library):
    with open(f"./nix/{library}_pkg_versions.json", "r") as handle:
        versions = json.load(handle)

    return versions

def attempt_build(library, version, variant):
    cmd = ["nix", "build", f".#{variant}.{library}.{version}"]
    start = time.time()

    result = {}
    try:
        sp.check_output(cmd, stderr=sp.STDOUT)
        success = True
        stderr = ""
    except sp.CalledProcessError as e:
        stderr = e.output.decode()
        success = False

    result['build_time'] = time.time() - start
    result['success'] = success
    result['stderr'] = stderr.split('\n') if stderr else []

    return result

def valid_build_type(value):
    value = value.strip()
    valid_types = ["shim", "lib"]
    if value not in valid_types:
        raise argparse.ArgumentTypeError(f"'{value}' not from expected {', '.join(valid_types)}.")
    return value

def save_build_result(library, variant, version, result):
    resdir = Path(f"build_all/{variant}")
    resdir.mkdir(parents=True, exist_ok=True)
    try:
        # Update previous results
        with open(resdir / f"{library}.json", "r") as handle:
            prev_results = json.load(handle)
    # NOTE this is not ideal as the JSON decoding problem can be other than just an empty file
    except (FileNotFoundError, json.JSONDecodeError):
        prev_results = {}

    prev_results[version] = result
    with open(resdir / f"{library}.json", "w") as handle:
        json.dump(prev_results, handle, indent=4)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--library")
    parser.add_argument("-v", "--variant", default="shim", type=valid_build_type)
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
            print("Building all libraries")
            # Build all libraries by default
            for lib in libraries:
                print(f"Library: {lib}")
                for version in get_all_versions(lib):
                    result = attempt_build(lib, version, variant)
                    save_build_result(lib, variant, version, result)
                    print(f"{version}: {result['success']}")
        case lib if lib in libraries:
            print(f"Library: {library}")
            for version in get_all_versions(library):
                result = attempt_build(lib, version, variant)
                save_build_result(lib, variant, version, result)
                print(f"{version}: {result['success']}")
        case _:
            print(f"Unrecognized library '{library}'. Try one of: {', '.join(libraries)}.")


if __name__ == '__main__':
    main()
