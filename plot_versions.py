#!/usr/bin/env python3

import argparse
import json

from collections import defaultdict
from pathlib import Path

import pandas as pd

def get_all_versions(library):
    with open(f"./nix/{library}_pkg_versions.json", "r") as handle:
        versions = json.load(handle)
    return versions

def build_results_to_latex(library):
    versions = get_all_versions(library)
    lib_results = get_results(library, "lib")
    lib_rows = [r"{\color{blue}\cmark}" if lib_results[ver]["success"] else r"{\color{red}\xmark}" for ver in versions.keys()]

    shim_results = get_results(library, "shim")
    shim_rows = [r"{\color{blue}\cmark}" if shim_results[ver]["success"] else r"{\color{red}\xmark}" for ver in versions.keys()]
    # shim_rows = [shim_results[ver] for ver in versions.keys()]

    cleaned_versions = [v.replace('_', r"{\_}") for v in versions.keys()]
    df = pd.DataFrame(dict(Versions=cleaned_versions, Library=lib_rows, Shim=shim_rows))
    # FIXME there should be a translation from `openssl` -> `OpenSSL` etc.
    tabledir = Path(f"./build_all/tables")
    tabledir.mkdir(parents=True, exist_ok=True)
    with open(tabledir / f"{library}.tex", "w") as handle:
        handle.write(df.to_latex(index=False, caption=library, label=f"{library}-lib-and-shim-builds"))

def get_results(library, variant):
    with open(f"./build_all/{variant}/{library}.json", "r") as handle:
        return json.load(handle)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--library")
    # parser.add_argument("-v", "--variant", default="shim", type=valid_build_type)
    args = parser.parse_args()
    library = args.library
    # variant = args.variant

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
            # print("Building all libraries")
            # # Build all libraries by default
            for lib in libraries:
                build_results_to_latex(lib)
            #     print(f"Library: {lib}")
            #     for version in get_all_versions(lib):
            #         result = attempt_build(lib, version, variant)
            #         save_build_result(lib, variant, version, result)
            #         print(f"{version}: {result['success']}")
        case lib if lib in libraries:
            build_results_to_latex(lib)
            # print(f"Library: {library}")
            # for version in get_all_versions(library):
            #     result = attempt_build(lib, version, variant)
            #     save_build_result(lib, variant, version, result)
            #     print(f"{version}: {result['success']}")
        case _:
            pass
            print(f"Unrecognized library '{library}'. Try one of: {', '.join(libraries)}.")


if __name__ == '__main__':
    main()
