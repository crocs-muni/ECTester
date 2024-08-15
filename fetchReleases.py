#!/usr/bin/env python3

import argparse

import json
import jinja2
import re
import requests
import shutil
import tempfile

import pathlib
import subprocess as sp

from base64 import b32encode, b32decode, b64encode, b16decode
from bs4 import BeautifulSoup
from packaging.version import parse as parse_version, Version

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

def serialize_versions(pkg, renders, versions):
    sorted_versions = {k: {kk: vv for kk, vv in v.items() if kk != "sort"} for k, v in sorted(versions.items(), key=lambda item: item[1]["sort"], reverse=True)}

    # all_versions = all_versions_template.render(pkg_versions=renders).strip()
    # with open(f"./nix/{pkg}_pkg_versions.nix", "w") as handle:
    #     handle.write(all_versions)

    with open(f"./nix/{pkg}_pkg_versions.json", "w") as handle:
        json.dump(sorted_versions, handle, indent=4)

def fetch_botan():
    pkg = "botan"
    # NOTE: this way omits the older releases at https://botan.randombit.net/releases/old
    release_list = "https://botan.randombit.net/releases/"
    download_url = "https://botan.randombit.net/releases/{version}"
    resp = requests.get(release_list)
    soup = BeautifulSoup(resp.content, 'html.parser')

    single_version_template = env.from_string("""{{ flat_version }} = buildECTesterStandalone {
    {{ pkg }} = { version="{{ version }}"; source_extension="{{ ext }}"; hash="{{ digest }}"; };
  };""")

    renders = []
    versions = {}
    for link in soup.find_all("a"):
        if link.text.startswith("Botan") and not link.text.endswith('.asc'):
            download_link = download_url.format(version=link['href'])

            match = re.match(r"Botan-(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)\.(?P<ext>.*)", link.text)
            if match['major'] == "3":
                # TODO: Handle Botan-3
                print(f"Skipping Botan-3 {match}")
                continue
            version = f"{match['major']}.{match['minor']}.{match['patch']}"
            ext = f"{match['ext']}"

            digest = get_source_hash(download_link)
            # NOTE: use underscore to separate the versions?
            flat_version = f"v{match['major']}{match['minor']}{match['patch']}"
            print(f"{version}:{digest}")

            rendered = single_version_template.render(pkg=pkg, digest=digest, ext=ext, flat_version=flat_version, version=version).strip()
            renders.append(rendered)
            versions[flat_version] = {
                "version": version,
                "source_extension": ext,
                "hash": digest,
                "sort": parse_version(version)
            }
    serialize_versions(pkg, renders, versions)

def fetch_cryptopp():
    pkg = "cryptopp"
    owner = "weidai11"
    repo = "cryptopp"
    release_url = f"https://api.github.com/repos/{owner}/{repo}/releases"
    resp = requests.get(release_url)

    single_version_template = env.from_string("""{{ flat_version }} = buildECTesterStandalone {
    {{ pkg }} = { version="{{ version }}"; hash="{{ digest }}"; };
  };""")
    renders = []
    versions = {}
    for release in resp.json():
        if not release['draft'] and not release['prerelease']:
            _, *version_values = release['tag_name'].split('_')
            underscored_version = '_'.join(version_values)
            flat_version = "v" + "".join(version_values)
            download_url = f"https://github.com/{owner}/{repo}/archive/{release['tag_name']}.tar.gz"
            digest = get_source_hash(download_url, unpack=True)
            print(f"{underscored_version}:{digest}")

            rendered = single_version_template.render(pkg=pkg, digest=digest, flat_version=flat_version, version=underscored_version).strip()
            renders.append(rendered)
            versions[flat_version] = {
                "version": underscored_version,
                "hash": digest,
                "sort": parse_version(underscored_version.replace("_", "."))
            }
    serialize_versions(pkg, renders, versions)

def fetch_openssl():
    pkg = "openssl"
    owner = "openssl"
    repo = "openssl"
    release_url = f"https://api.github.com/repos/{owner}/{repo}/releases"
    resp_releases = requests.get(release_url)
    tags_url = f"https://api.github.com/repos/{owner}/{repo}/git/matching-refs/tags"
    resp_tags = requests.get(tags_url)

    tags = [release["tag_name"] for release in resp_releases.json() if not release["draft"] and not release["prerelease"]]
    tags += [tag_ref["ref"].split("/")[-1] for tag_ref in resp_tags.json() if tag_ref["ref"].startswith("refs/tags/openssl-") or tag_ref["ref"].startswith("refs/tags/OpenSSL_")]
    tags = list(filter(lambda tag: "FIPS" not in tag and "reformat" not in tag and "alpha" not in tag and "beta" not in tag and "pre" not in tag, tags))
    for tag in tags:
        print(tag)
    

    single_version_template = env.from_string("""{{ flat_version }} = buildECTesterStandalone {
    {{ pkg }} = { version="{{ version }}"; hash="{{ digest }}"; };
  };""")
    renders = []
    versions = {}
    for tag in tags:
        print(tag)
        if tag.startswith("OpenSSL_"):
            match = re.match(r"OpenSSL_(?P<major>\d+)_(?P<minor>\d+)_(?P<patch>\d+)(?P<ext>.*)", tag)
            sort_version = f"{match['major']}.{match['minor']}.{match['patch']}{'+' + match['ext'] if match['ext'] else ''}"
            dotted_version = f"{match['major']}.{match['minor']}.{match['patch']}{ match['ext'] if match['ext'] else ''}"
        else:
            try: 
                _, dotted_version = tag.split('-')
                sort_version = dotted_version
            except ValueError:
                continue
        flat_version = "v" + "".join(dotted_version.split('.'))
        download_url = f"https://www.openssl.org/source/openssl-{dotted_version}.tar.gz"
        old_url = f"https://www.openssl.org/source/old/openssl-{dotted_version}.tar.gz"
        try:
            digest = get_source_hash(download_url)
        except Exception:
            try:
                digest = get_source_hash(old_url)
            except Exception:
                print(f"Skipping {dotted_version} (unavailable)")
                continue
        print(f"{dotted_version}:{digest}")
        versions[flat_version] = {
            "version": dotted_version,
            "hash": digest,
            "sort": parse_version(sort_version)
        }

        rendered = single_version_template.render(pkg=pkg, digest=digest, flat_version=flat_version, version=dotted_version).strip()
        renders.append(rendered)
    serialize_versions(pkg, renders, versions)


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
    versions = {}
    for link in soup.find_all("a"):
        if link.text.startswith("libgcrypt") and link.text.endswith("tar.bz2"):
            download_link = download_url.format(version=link['href'])

            match = re.match(r"libgcrypt-(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?P<dont>_do_not_use)?\.(?P<ext>.*)", link.text)
            version = f"{match['major']}.{match['minor']}.{match['patch']}"

            digest = get_source_hash(download_link)
            print(f"{version}:{digest}")

            flat_version = f"v{match['major']}{match['minor']}{match['patch']}"
            if match['dont']:
                flat_version += "_do_not_use"

            rendered = single_version_template.render(pkg=pkg, digest=digest, flat_version=flat_version, version=version).strip()
            renders.append(rendered)
            versions[flat_version] = {
                "version": version,
                "hash": digest,
                "sort": parse_version(version)
            }
    serialize_versions(pkg, renders, versions)

def fetch_boringssl():
    pkg = "boringssl"

    single_version_template = env.from_string("""{{ flat_version }} = buildECTesterStandalone {
    {{ pkg }} = { rev="{{ rev }}"; hash="{{ digest }}"; };
  };""")
    renders = []
    versions = {}
    with tempfile.TemporaryDirectory() as repodir, tempfile.TemporaryDirectory() as gitdir:
        repodir = pathlib.Path(repodir)
        gitdir = pathlib.Path(gitdir)
        sp.run(["git", "clone", "https://boringssl.googlesource.com/boringssl", repodir])
        # NOTE: we need to get rid of the .git so that it is not included in the derivation hash
        shutil.move(repodir / ".git", gitdir)

        output = sp.check_output(["git", "-C", str(repodir), "--git-dir", str(gitdir / ".git"), "log", "--pretty=format:%H"])
        refs = output.decode().split('\n')

        for i, rev in enumerate(refs[:100]):
            sp.run(["git", "-C", str(repodir), "--git-dir", str(gitdir / ".git"), "checkout", rev])
            digest = sp.check_output(["nix", "hash", "path", str(repodir)]).decode().strip()
            print(f"{i + 1: 4d}:{rev}:{digest}")
            abbrev_commit = str(rev[:8])

            rendered = single_version_template.render(pkg=pkg, digest=digest, flat_version=f"r{abbrev_commit}", rev=rev).strip()
            renders.append(rendered)
            versions[f"r{abbrev_commit}"] = {
                "rev": rev,
                "hash": digest,
                "sort": i
            }
    serialize_versions(pkg, renders, versions)

def fetch_mbedtls():
    # Mbed-TLS/mbedtls
    pkg = "mbedtls"
    owner = "Mbed-TLS"
    repo = "mbedtls"
    release_url = f"https://api.github.com/repos/{owner}/{repo}/releases"
    resp = requests.get(release_url)

    single_version_template = env.from_string("""{{ flat_version }} = buildECTesterStandalone {
    {{ pkg }} = { version="{{ version }}"; hash="{{ digest }}"; };
  };""")
    renders = []
    versions = {}
    for release in resp.json():
        if not release['draft'] and not release['prerelease']:
            tag = release["tag_name"]
            version = tag.replace("mbedtls-", "v")
            flat_version = version.replace('.', '')
            download_url = f"https://github.com/{owner}/{repo}/archive/{tag}.tar.gz"
            if version == "v3.6.0":
                # TODO: Special case for the time being
                digest = "sha256-tCwAKoTvY8VCjcTPNwS3DeitflhpKHLr6ygHZDbR6wQ="
            else:
                digest = get_source_hash(download_url, unpack=True)

            print(f"{version}:{digest}")

            rendered = single_version_template.render(pkg=pkg, digest=digest, flat_version=flat_version, version=version).strip()
            renders.append(rendered)
            versions[flat_version] = {
                "version": version,
                "hash": digest,
                "tag": tag,
                "sort": parse_version(version)
            }
    serialize_versions(pkg, renders, versions)

def fetch_ippcp():
    # https://api.github.com/repos/intel/ipp-crypto/releases
    pkg = "ippcp"
    owner = "intel"
    repo = "ipp-crypto"
    release_url = f"https://api.github.com/repos/{owner}/{repo}/releases"
    resp = requests.get(release_url)

    single_version_template = env.from_string("""{{ flat_version }} = buildECTesterStandalone {
    {{ pkg }} = { version="{{ version }}"; hash="{{ digest }}"; };
  };""")
    renders = []
    versions = {}
    for release in resp.json():
        if not release['draft'] and not release['prerelease']:
            version = release['tag_name'].split('_')[1]
            flat_version = "v" + version.replace('.', '_')
            download_url = f"https://github.com/{owner}/{repo}/archive/{release['tag_name']}.tar.gz"
            digest = get_source_hash(download_url, unpack=True)
            print(f"{version}:{digest}")

            rendered = single_version_template.render(pkg=pkg, digest=digest, flat_version=flat_version, version=version).strip()
            renders.append(rendered)
            versions[flat_version] = {
                "version": version,
                "hash": digest,
                "sort": parse_version(version.replace("u", "+u"))
            }
    serialize_versions(pkg, renders, versions)

def fetch_nettle():
    # https://api.github.com/repos/intel/ipp-crypto/releases
    pkg = "nettle"
    owner = "gnutls"
    repo = "nettle"
    release_url = f"https://api.github.com/repos/{owner}/{repo}/tags"
    resp = requests.get(release_url)

    single_version_template = env.from_string("""{{ flat_version }} = buildECTesterStandalone {
    {{ pkg }} = { version="{{ version }}"; tag="{{ tag }}"; hash="{{ digest }}"; };
  };""")
    renders = []
    versions = {}
    for tag in resp.json():
        if tag['name'] == 'release_nettle_0.2.20010617':
            continue
        version = tag['name'].split('_')[1]
        # NOTE skip release candidates
        if re.search(r'\drc\d', version):
            continue
        flat_version = "v" + version.replace('.', '_')
        # download_url = f"https://github.com/{owner}/{repo}/archive/{tag['name']}.tar.gz"
        download_url = f"mirror://gnu/nettle/nettle-{version}.tar.gz"
        digest = get_source_hash(download_url, unpack=False)
        print(f"{version}:{digest}")

        rendered = single_version_template.render(
                pkg=pkg, digest=digest, flat_version=flat_version, tag=tag['name'], version=version).strip()
        renders.append(rendered)
        versions[flat_version] = {
            "version": version,
            "tag": tag['name'],
            "hash": digest,
            "sort": parse_version(version)
        }
    serialize_versions(pkg, renders, versions)


def fetch_libressl():
    pkg = "libressl"
    release_list = "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/"
    download_url = "mirror://openbsd/LibreSSL/libressl-{version}.tar.gz"
    resp = requests.get(release_list)
    soup = BeautifulSoup(resp.content, 'html.parser')

    single_version_template = env.from_string("""{{ flat_version }} = buildECTesterStandalone {
    {{ pkg }} = { version="{{ version }}"; hash="{{ digest }}"; };
  };""")

    renders = []
    versions = {}
    for link in soup.find_all("a"):
        if link.text.startswith("libressl") and link.text.endswith('.tar.gz'):
            match = re.match(r"libressl-(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)\.tar.gz", link.text)
            version = f"{match['major']}.{match['minor']}.{match['patch']}"
            download_link = download_url.format(version=version)
            digest = get_source_hash(download_link)
            print(f"{version}:{digest}")
            # NOTE: use underscore to separate the versions?
            flat_version = f"v{match['major']}{match['minor']}{match['patch']}"

            rendered = single_version_template.render(pkg=pkg, digest=digest, flat_version=flat_version, version=version).strip()
            renders.append(rendered)
            versions[flat_version] = {
                "version": version,
                "hash": digest,
                "sort": parse_version(version)
            }
    serialize_versions(pkg, renders, versions)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("lib")
    args = parser.parse_args()

    print(f"Fetching versions and source hashes for: {args.lib}")

    match args.lib:
        case "botan":
            fetch_botan()
        case "cryptopp":
            fetch_cryptopp()
        case "openssl":
            fetch_openssl()
        case "boringssl":
            fetch_boringssl()
        case "gcrypt":
            fetch_gcrypt()
        case "mbedtls":
            fetch_mbedtls()
        case "ippcp":
            fetch_ippcp()
        case "nettle":
            fetch_nettle()
        case "libressl":
            fetch_libressl()
        case "all":
            fetch_botan()
            fetch_cryptopp()
            fetch_openssl()
            fetch_boringssl()
            fetch_gcrypt()
            fetch_mbedtls()
            fetch_ippcp()
            fetch_nettle()
            fetch_libressl()
        case _:
            print("Unknown library")


if __name__ == '__main__':
    main()
