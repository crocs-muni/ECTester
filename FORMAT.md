# Format
CSV based, little-endian hexadecimal values.

## Curves
### Prime field
`p,a,b,gx,gy,n,h`


### Binary field
`m,e1,e2,e3,a,b,gx,gy,n,h`

## Key material
### Keypair
`wx,wy,s`

### Public key
`wx,wy`

### Private key
`s`

# Notation
 - `p` - prime F_p
 - `m` - binary field exponent F_2^m
   - e1 - largest exponent of the field polynomial
   - e2 - middle exponenet of the field polynomial, or `0000` if field poly is a trinomial
   - e3 - smallest exponent (except zero) of the field polynomial, or `0000` if field poly is a trinomial
 - `a` - a parameter in short Weierstrass curve equation
 - `b` - b parameter in short Weierstrass curve equation
 - `gx` - x coordinate of the curve base-point g
 - `gy` - y coordinate of the curve base-point g
 - `n` - the base-point order
 - `h` - the base-point cofactor
 - `wx` - the x coordinate of the public key
 - `wy` - the y coordinate of th public key
 - `s` - the private key value