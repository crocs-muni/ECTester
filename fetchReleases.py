#!/usr/bin/env python3

import argparse

import json
import jinja2
import re
import requests

import subprocess as sp

from base64 import b32encode, b32decode, b64encode, b16decode
from bs4 import BeautifulSoup

env = jinja2.Environment()

all_versions_template = env.from_string("""{
  buildECTesterStandalone
}:
{ {% for version in pkg_versions %}
  {{ version }} {% endfor %}
}""")

def get_source_hash(url, unpack=False):
    digest_type = "sha256"

    cmd = ["nix-prefetch-url"]
    if unpack:
        cmd.append("--unpack")
    cmd.extend(["--type", digest_type, url])

    digest_nixbase32 = sp.check_output(cmd, stderr=sp.DEVNULL).strip()
    digest_sri = sp.check_output(["nix", "hash", "to-sri", "--type", digest_type, digest_nixbase32.decode()], stderr=sp.DEVNULL).strip().decode()
    return digest_sri

def fetch_botan():
    # NOTE: this way omits the older releases at https://botan.randombit.net/releases/old
    release_list = "https://botan.randombit.net/releases/"
    download_url = "https://botan.randombit.net/releases/{version}"
    resp = requests.get(release_list)
    soup = BeautifulSoup(resp.content, 'html.parser')

    single_version_template = env.from_string("""{{ flat_version }} = buildECTesterStandalone {
    {{ pkg }} = { version="{{ version }}"; source_extension="{{ ext }}"; hash="{{ digest }}"; };
  };""")

    renders = []
    for link in soup.find_all("a"):
        if link.text.startswith("Botan") and not link.text.endswith('.asc'):
            download_link = download_url.format(version=link['href'])

            match = re.match(r"Botan-(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)\.(?P<ext>.*)", link.text)
            version = f"{match['major']}.{match['minor']}.{match['patch']}"
            ext = f"{match['ext']}"

            digest = get_source_hash(download_link)
            # NOTE: use underscore to separate the versions?
            flat_version = f"v{match['major']}{match['minor']}{match['patch']}"

            rendered = single_version_template.render(pkg="botan", digest=digest, ext=ext, flat_version=flat_version, version=version).strip()
            renders.append(rendered)

    all_versions = all_versions_template.render(pkg_versions=renders).strip()
    with open("./nix/botan_pkg_versions.nix", "w") as handle:
        handle.write(all_versions)

def fetch_cryptopp():
    owner = "weidai11"
    repo = "cryptopp"
    release_url = f"https://api.github.com/repos/{owner}/{repo}/releases"
    resp = requests.get(release_url)

    single_version_template = env.from_string("""{{ flat_version }} = buildECTesterStandalone {
    {{ pkg }} = { version="{{ version }}"; hash="{{ digest }}"; };
  };""")
    renders = []
    for release in resp.json():
        if not release['draft'] and not release['prerelease']:
            _, *version_values = release['tag_name'].split('_')
            underscored_version = '_'.join(version_values)
            flat_version = "v" + "".join(version_values)
            download_url = f"https://github.com/{owner}/{repo}/archive/{release['tag_name']}.tar.gz"
            digest = get_source_hash(download_url, unpack=True)


            rendered = single_version_template.render(pkg="cryptopp", digest=digest, flat_version=flat_version, version=underscored_version).strip()
            renders.append(rendered)

    all_versions = all_versions_template.render(pkg_versions=renders).strip()
    with open("./nix/cryptopp_pkg_versions.nix", "w") as handle:
        handle.write(all_versions)

def fetch_openssl():
    pkg = "openssl"
    owner = "openssl"
    repo = "openssl"
    release_url = f"https://api.github.com/repos/{owner}/{repo}/releases"
    resp = requests.get(release_url)

    single_version_template = env.from_string("""{{ flat_version }} = buildECTesterStandalone {
    {{ pkg }} = { version="{{ version }}"; hash="{{ digest }}"; };
  };""")
    renders = []
    for release in resp.json():
        if not release['draft'] and not release['prerelease']:
            try: 
                _, dotted_version = release['tag_name'].split('-')
            except ValueError:
                continue
            flat_version = "v" + "".join(dotted_version.split('.'))
            download_url = f"https://github.com/{owner}/{repo}/archive/{release['tag_name']}.tar.gz"
            digest = get_source_hash(download_url)


            rendered = single_version_template.render(pkg=pkg, digest=digest, flat_version=flat_version, version=dotted_version).strip()
            renders.append(rendered)

    all_versions = all_versions_template.render(pkg_versions=renders).strip()
    with open(f"./nix/{pkg}_pkg_versions.nix", "w") as handle:
        handle.write(all_versions)

def fetch_tomcrypt():
    # fetch libtomcrypt
    pass

def fetch_gcrypt():

    pkg = "gcrypt"
    release_list = "https://gnupg.org/ftp/gcrypt/libgcrypt/"
    download_url = "https://gnupg.org/ftp/gcrypt/libgcrypt/{version}"
    resp = requests.get(release_list)
    soup = BeautifulSoup(resp.content, 'html.parser')

    single_version_template = env.from_string("""{{ flat_version }} = buildECTesterStandalone {
    {{ pkg }} = { version="{{ version }}";  hash="{{ digest }}"; };
  };""")

    renders = []
    for link in soup.find_all("a"):
        if link.text.startswith("libgcrypt") and link.text.endswith("tar.bz2"):
            download_link = download_url.format(version=link['href'])

            match = re.match(r"libgcrypt-(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?P<dont>_do_not_use)?\.(?P<ext>.*)", link.text)
            version = f"{match['major']}.{match['minor']}.{match['patch']}"
            print(version)

            digest = get_source_hash(download_link)
            print(digest)

            flat_version = f"v{match['major']}{match['minor']}{match['patch']}"
            if match['dont']:
                flat_version += "_do_not_use"


            rendered = single_version_template.render(pkg=pkg, digest=digest, flat_version=flat_version, version=version).strip()
            renders.append(rendered)

    all_versions = all_versions_template.render(pkg_versions=renders).strip()
    with open("./nix/gcrypt_pkg_versions.nix", "w") as handle:
        handle.write(all_versions)





def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("lib")
    args = parser.parse_args()

    match args.lib:
        case "botan":
            fetch_botan()
        case "cryptopp":
            fetch_cryptopp()
        case "openssl":
            fetch_openssl()
        case "gcrypt":
            fetch_gcrypt()


if __name__ == '__main__':
    main()
