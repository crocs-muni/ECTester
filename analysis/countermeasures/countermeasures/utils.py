from pyecsca.ec.mult import DoubleAndAddMultiplier
from pyecsca.ec.signature import ECDSA_SHA1, SignatureResult
from pyecsca.ec.model import ShortWeierstrassModel
from pyecsca.ec.mod import Mod, mod
from pyecsca.ec.error import NonInvertibleError
import os
from hashlib import sha1
from pyasn1.codec.der.decoder import decode
from pyasn1.type.univ import Sequence
from pyecsca.ec.point import Point

def get_point_bytes(path):
    with open(path, "r") as f:
        line = f.read()
        sx, sy = line.split(",")
        bx = bytes.fromhex(sx[2:])
        by = bytes.fromhex(sy[2:])
        point = bytes([0x04]) + bx + by
        return point

def tuple_to_point(tuple_int, params, coords):
    x,y = tuple_int
    return Point(X=mod(x, params.curve.prime),Y=mod(y, params.curve.prime),Z=mod(1, params.curve.prime), model=coords)


def csv_to_point(path, params, coords):
    with open(path,"r") as f:
        line = f.read()
        x, y = line.split(",")
    xy = int(x,16),int(y,16)
    return tuple_to_point(xy, params,coords)

def parse_04point(string):
    assert string.startswith("04")
    x,y = map(lambda x: int(x,16),[string[2:][:len(string)//2-1],string[2:][len(string)//2-1:]])
    return x,y

def read_curve_params(path):
    with open(path) as f:
        return f.read().strip()


def serialize_ecdh_response(ecdhresponse, curve, point, key):
    error = str(int(ecdhresponse.error))
    params = ",".join(map(lambda x: x.hex(), ecdhresponse.params))
    apdu = ecdhresponse.resp.data.hex()
    secret = ecdhresponse.secret.hex()
    success = str(int(ecdhresponse.success))
    sws = ",".join(map(str, ecdhresponse.sws))
    point = point.hex()
    key = hex(key)
    return ";".join([success, error, secret, key, point, curve, params, apdu, sws])


def recover_nonce(params, data, key, point_bytes, signature_result):
    point = params.curve.decode_point(point_bytes)
    model = ShortWeierstrassModel().coordinates["projective"]
    sig = ECDSA_SHA1(
        DoubleAndAddMultiplier(
            model.formulas["add-2007-bl"], model.formulas["dbl-2007-bl"]
        ),
        params.to_coords(model),
        pubkey=point.to_model(model, params.curve.to_coords(model)),
        privkey=key,
    )
    digest = sig.hash_algo(data).digest()
    z = int.from_bytes(digest, byteorder="big")
    if len(digest) * 8 > sig.params.order.bit_length():
        z >>= len(digest) * 8 - sig.params.order.bit_length()
    r, s = signature_result.r, signature_result.s
    s = mod(int(s), sig.params.order)
    r = mod(int(r), sig.params.order)
    try:
        nonce = s.inverse() * (mod(z, sig.params.order) + r * sig.privkey)
    except NonInvertibleError:
        return 0
    sig.mult.init(sig.params, sig.params.generator)
    point = sig.mult.multiply(int(nonce))
    affine_point = point.to_affine()
    # assert r == mod(int(affine_point.x), sig.params.order)
    return nonce


def serialize_ecdsa_response(
    response, data, domainparams, key, curve_csv, point_bytes, valid=None
):
    error = str(int(response.error))
    params = ",".join(map(lambda x: x.hex(), response.params))
    apdu = response.resp.data.hex()
    signature = response.signature.hex()
    success = str(int(response.success))
    sws = ",".join(map(str, response.sws))
    point_bytes_hex = point_bytes.hex()
    key_hex = hex(key)
    data_hex = data.hex()
    nonce = recover_nonce(
        domainparams,
        data,
        key,
        point_bytes,
        SignatureResult.from_DER(response.signature),
    )
    nonce_hex = hex(int(nonce))
    valid_str = "" if valid is None else str(valid)
    return ";".join(
        [
            success,
            error,
            signature,
            valid_str,
            data_hex,
            nonce_hex,
            key_hex,
            point_bytes_hex,
            curve_csv,
            params,
            apdu,
            sws,
        ]
    )


def serialize_keygen_response(response, key, curve_csv, point_bytes):
    error = str(int(response.error))
    params = ",".join(map(lambda x: x.hex(), response.params))
    apdu = response.resp.data.hex()
    success = str(int(response.success))
    sws = ",".join(map(str, response.sws))
    point_bytes_hex = point_bytes.hex()
    key_hex = hex(key)
    return ";".join(
        [success, error, key_hex, point_bytes_hex, curve_csv, params, apdu, sws]
    )


def safe_save(header, result_lines, filename):
    if os.path.isfile(filename):
        print(f"Measurement already exists ({filename})")
        return
    tmp = filename + ".tmp"
    with open(tmp, "w") as f:
        f.write(f"{header}\n")
        for line in result_lines:
            f.write(f"{line}\n")
    os.rename(tmp, filename)


def save_ecdh(result_lines, filename):
    header = "success;error;secret[SHA1];priv;pub;curve;params;apdu;sws"
    safe_save(header, result_lines, filename)


def save_ecdsa(result_lines, filename):
    header = "success;error;signature;valid;data;nonce;priv;pub;curve;params;apdu;sws"
    safe_save(header, result_lines, filename)


def save_keygen(result_lines, filename):
    header = "success;error;priv;pub;curve;params;apdu;sws"
    safe_save(header, result_lines, filename)


def parse_ecdsa_signature(signature_der):
    decoded_signature, _ = decode(signature_der, asn1Spec=Sequence())
    r = int(decoded_signature[0])
    s = int(decoded_signature[1])
    return r, s

def sha(value):
    h = hex(int(value))[2:]
    if len(h)%2!=0:
        h = "0"+h
    bh = bytes.fromhex(h)
    return int(sha1(bh).digest().hex(),16)
