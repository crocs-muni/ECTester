"""
This module is a collection of modules glued together, to provide basic
elliptic curve arithmetic for curves over prime and binary fields. It consists of
 - tinyec: https://github.com/alexmgr/tinyec (GPL v3 licensed)
 - pyfinite: https://github.com/emin63/pyfinite (MIT licensed)
 - modular square root from https://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python
 - and some of my own code: https://github.com/J08nY
"""

import abc
import random
from functools import reduce, wraps
from os import path


def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using
        Euler's criterion. p is a prime, a is
        relatively prime to p (if p divides
        a, then a|p = 0)

        Returns 1 if a has a square root modulo
        p, -1 otherwise.
    """
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


def is_prime(n, trials=50):
    """
    Miller-Rabin primality test.
    """
    s = 0
    d = n - 1
    while d % 2 == 0:
        d >>= 1
        s += 1
    assert (2 ** s * d == n - 1)

    def trial_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2 ** i * d, n) == n - 1:
                return False
        return True

    for i in range(trials):  # number of trials
        a = random.randrange(2, n)
        if trial_composite(a):
            return False
    return True


def gcd(a, b):
    """Euclid's greatest common denominator algorithm."""
    if abs(a) < abs(b):
        return gcd(b, a)

    while abs(b) > 0:
        q, r = divmod(a, b)
        a, b = b, r

    return a


def extgcd(a, b):
    """Extended Euclid's greatest common denominator algorithm."""
    if abs(b) > abs(a):
        (x, y, d) = extgcd(b, a)
        return y, x, d

    if abs(b) == 0:
        return 1, 0, a

    x1, x2, y1, y2 = 0, 1, 1, 0
    while abs(b) > 0:
        q, r = divmod(a, b)
        x = x2 - q * x1
        y = y2 - q * y1
        a, b, x2, x1, y2, y1 = b, r, x1, x, y1, y

    return x2, y2, a


def check(func):
    @wraps(func)
    def method(self, other):
        if isinstance(other, int):
            other = self.__class__(other, self.field)
        if type(self) is type(other):
            if self.field == other.field:
                return func(self, other)
            else:
                raise ValueError
        else:
            raise TypeError

    return method


class Mod(object):
    """An element x of ℤₙ."""

    def __init__(self, x: int, n: int):
        self.x = x % n
        self.field = n

    @check
    def __add__(self, other):
        return Mod((self.x + other.x) % self.field, self.field)

    @check
    def __radd__(self, other):
        return self + other

    @check
    def __sub__(self, other):
        return Mod((self.x - other.x) % self.field, self.field)

    @check
    def __rsub__(self, other):
        return -self + other

    def __neg__(self):
        return Mod(self.field - self.x, self.field)

    def inverse(self):
        x, y, d = extgcd(self.x, self.field)
        return Mod(x, self.field)

    def __invert__(self):
        return self.inverse()

    @check
    def __mul__(self, other):
        return Mod((self.x * other.x) % self.field, self.field)

    @check
    def __rmul__(self, other):
        return self * other

    @check
    def __truediv__(self, other):
        return self * ~other

    @check
    def __rtruediv__(self, other):
        return ~self * other

    @check
    def __floordiv__(self, other):
        return self * ~other

    @check
    def __rfloordiv__(self, other):
        return ~self * other

    @check
    def __div__(self, other):
        return self.__floordiv__(other)

    @check
    def __rdiv__(self, other):
        return self.__rfloordiv__(other)

    @check
    def __divmod__(self, divisor):
        q, r = divmod(self.x, divisor.x)
        return Mod(q, self.field), Mod(r, self.field)

    def __int__(self):
        return self.x

    def __eq__(self, other):
        if type(other) is not Mod:
            return False
        return self.x == other.x and self.field == other.field

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return str(self.x)

    def __pow__(self, n):
        if not isinstance(n, int):
            raise TypeError
        if n == 0:
            return Mod(1, self.field)
        if n < 0:
            return (~self) ** -n
        if n == 1:
            return self
        if n == 2:
            return self * self

        q = self
        r = self if n & 1 else Mod(1, self.field)

        i = 2
        while i <= n:
            q = (q * q)
            if n & i == i:
                r = (q * r)
            i = i << 1
        return r

    def sqrt(self):
        if not is_prime(self.field):
            raise NotImplementedError
        # Simple cases
        if legendre_symbol(self.x, self.field) != 1 or self.x == 0 or self.field == 2:
            raise ValueError("Not a quadratic residue.")
        if self.field % 4 == 3:
            return self ** ((self.field + 1) // 4)

        a = self.x
        p = self.field
        s = p - 1
        e = 0
        while s % 2 == 0:
            s /= 2
            e += 1

        n = 2
        while legendre_symbol(n, p) != -1:
            n += 1

        x = pow(a, (s + 1) / 2, p)
        b = pow(a, s, p)
        g = pow(n, s, p)
        r = e

        while True:
            t = b
            m = 0
            for m in range(r):
                if t == 1:
                    break
                t = pow(t, 2, p)

            if m == 0:
                return Mod(x, p)

            gs = pow(g, 2 ** (r - m - 1), p)
            g = (gs * gs) % p
            x = (x * gs) % p
            b = (b * g) % p
            r = m


class FField(object):
    """
    The FField class implements a binary field.
    """

    def __init__(self, n, gen):
        """
        This method constructs the field GF(2^n).  It takes two
        required arguments, n and gen,
        representing the coefficients of the generator polynomial
        (of degree n) to use.
        Note that you can look at the generator for the field object
        F by looking at F.generator.
        """

        self.n = n
        if len(gen) != n + 1:
            full_gen = [0] * (n + 1)
            for i in gen:
                full_gen[i] = 1
            gen = full_gen[::-1]
        self.generator = self.to_element(gen)
        self.unity = 1

    def add(self, x, y):
        """
        Adds two field elements and returns the result.
        """

        return x ^ y

    def subtract(self, x, y):
        """
        Subtracts the second argument from the first and returns
        the result.  In fields of characteristic two this is the same
        as the Add method.
        """
        return x ^ y

    def multiply(self, f, v):
        """
        Multiplies two field elements (modulo the generator
        self.generator) and returns the result.

        See MultiplyWithoutReducing if you don't want multiplication
        modulo self.generator.
        """
        m = self.multiply_no_reduce(f, v)
        return self.full_division(m, self.generator, self.find_degree(m), self.n)[1]

    def inverse(self, f):
        """
        Computes the multiplicative inverse of its argument and
        returns the result.
        """
        return self.ext_gcd(self.unity, f, self.generator, self.find_degree(f), self.n)[1]

    def divide(self, f, v):
        """
        Divide(f,v) returns f * v^-1.
        """
        return self.multiply(f, self.inverse(v))

    def exponentiate(self, f, n):
        """
        Exponentiate(f, n) returns f^n.
        """
        if not isinstance(n, int):
            raise TypeError
        if n == 0:
            return self.unity
        if n < 0:
            f = self.inverse(f)
            n = -n
        if n == 1:
            return f
        if n == 2:
            return self.multiply(f, f)

        q = f
        r = f if n & 1 else self.unity

        i = 2
        while i <= n:
            q = self.multiply(q, q)
            if n & i == i:
                r = self.multiply(q, r)
            i = i << 1
        return r

    def sqrt(self, f):
        return self.exponentiate(f, (2 ** self.n) - 1)

    def trace(self, f):
        t = f
        for _ in range(1, self.n):
            t = self.add(self.multiply(t, t), f)
        return t

    def half_trace(self, f):
        if self.n % 2 != 1:
            raise ValueError
        h = f
        for _ in range(1, (self.n - 1) // 2):
            h = self.multiply(h, h)
            h = self.add(self.multiply(h, h), f)
        return h

    def find_degree(self, v):
        """
        Find the degree of the polynomial representing the input field
        element v.  This takes O(degree(v)) operations.

        A faster version requiring only O(log(degree(v)))
        could be written using binary search...
        """
        if v:
            return v.bit_length() - 1
        else:
            return 0

    def multiply_no_reduce(self, f, v):
        """
        Multiplies two field elements and does not take the result
        modulo self.generator.  You probably should not use this
        unless you know what you are doing; look at Multiply instead.
        """

        result = 0
        mask = self.unity
        for i in range(self.n + 1):
            if mask & v:
                result = result ^ f
            f = f << 1
            mask = mask << 1
        return result

    def ext_gcd(self, d, a, b, a_degree, b_degree):
        """
        Takes arguments (d,a,b,aDegree,bDegree) where d = gcd(a,b)
        and returns the result of the extended Euclid algorithm
        on (d,a,b).
        """
        if b == 0:
            return a, self.unity, 0
        else:
            (floorADivB, aModB) = self.full_division(a, b, a_degree, b_degree)
            (d, x, y) = self.ext_gcd(d, b, aModB, b_degree, self.find_degree(aModB))
            return d, y, self.subtract(x, self.multiply(floorADivB, y))

    def full_division(self, f, v, f_degree, v_degree):
        """
        Takes four arguments, f, v, fDegree, and vDegree where
        fDegree and vDegree are the degrees of the field elements
        f and v represented as a polynomials.
        This method returns the field elements a and b such that

            f(x) = a(x) * v(x) + b(x).

        That is, a is the divisor and b is the remainder, or in
        other words a is like floor(f/v) and b is like f modulo v.
        """

        result = 0
        mask = self.unity << f_degree
        for i in range(f_degree, v_degree - 1, -1):
            if mask & f:
                result = result ^ (self.unity << (i - v_degree))
                f = self.subtract(f, v << (i - v_degree))
            mask = mask >> self.unity
        return result, f

    def coefficients(self, f):
        """
        Show coefficients of input field element represented as a
        polynomial in decreasing order.
        """

        result = []
        for i in range(self.n, -1, -1):
            if (self.unity << i) & f:
                result.append(1)
            else:
                result.append(0)

        return result

    def polynomial(self, f):
        """
        Show input field element represented as a polynomial.
        """

        f_degree = self.find_degree(f)
        result = ''

        if f == 0:
            return '0'

        for i in range(f_degree, 0, -1):
            if (1 << i) & f:
                result = result + (' x^' + repr(i))
        if 1 & f:
            result = result + ' ' + repr(1)
        return result.strip().replace(' ', ' + ')

    def to_element(self, l):
        """
        This method takes as input a binary list (e.g. [1, 0, 1, 1])
        and converts it to a decimal representation of a field element.
        For example, [1, 0, 1, 1] is mapped to 8 | 2 | 1 = 11.

        Note if the input list is of degree >= to the degree of the
        generator for the field, then you will have to call take the
        result modulo the generator to get a proper element in the
        field.
        """

        temp = map(lambda a, b: a << b, l, range(len(l) - 1, -1, -1))
        return reduce(lambda a, b: a | b, temp)

    def __str__(self):
        return "F_(2^{}): {}".format(self.n, self.polynomial(self.generator))

    def __repr__(self):
        return str(self)


class FElement(object):
    """
    This class provides field elements which overload the
    +,-,*,%,//,/ operators to be the appropriate field operation.
    Note that before creating FElement objects you must first
    create an FField object.
    """

    def __init__(self, f, field):
        """
        The constructor takes two arguments, field, and e where
        field is an FField object and e is an integer representing
        an element in FField.

        The result is a new FElement instance.
        """
        self.f = f
        self.field = field

    @check
    def __add__(self, other):
        return FElement(self.field.add(self.f, other.f), self.field)

    @check
    def __sub__(self, other):
        return FElement(self.field.add(self.f, other.f), self.field)

    def __neg__(self):
        return self

    @check
    def __mul__(self, other):
        return FElement(self.field.multiply(self.f, other.f), self.field)

    @check
    def __floordiv__(self, o):
        return FElement(self.field.full_division(self.f, o.f,
                                                 self.field.find_degree(self.f),
                                                 self.field.find_degree(o.f))[0], self.field)

    @check
    def __truediv__(self, other):
        return FElement(self.field.divide(self.f, other.f), self.field)

    def __div__(self, *args, **kwargs):
        return self.__truediv__(*args, **kwargs)

    @check
    def __divmod__(self, other):
        d, m = self.field.full_division(self.f, other.f,
                                        self.field.find_degree(self.f),
                                        self.field.find_degree(other.f))
        return FElement(d, self.field), FElement(m, self.field)

    def inverse(self):
        return FElement(self.field.inverse(self.f), self.field)

    def __invert__(self):
        return self.inverse()

    def sqrt(self):
        return FElement(self.field.sqrt(self.f), self.field)

    def trace(self):
        return FElement(self.field.trace(self.f), self.field)

    def half_trace(self):
        return FElement(self.field.half_trace(self.f), self.field)

    def __pow__(self, power, modulo=None):
        return FElement(self.field.exponentiate(self.f, power), self.field)

    def __str__(self):
        return str(int(self))

    def __repr__(self):
        return str(self)

    def __int__(self):
        return self.f

    def __eq__(self, other):
        if not isinstance(other, FElement):
            return False
        if self.field != other.field:
            return False
        return self.f == other.f


class Curve(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, field, a, b, group, name=None):
        self.field = field
        if name is None:
            name = "undefined"
        self.name = name
        self.a = a
        self.b = b
        self.group = group
        self.g = Point(self, self.group.g[0], self.group.g[1])

    @abc.abstractmethod
    def is_singular(self):
        ...

    @abc.abstractmethod
    def on_curve(self, x, y):
        ...

    @abc.abstractmethod
    def add(self, x1, y1, x2, y2):
        ...

    @abc.abstractmethod
    def dbl(self, x, y):
        ...

    @abc.abstractmethod
    def neg(self, x, y):
        ...

    @abc.abstractmethod
    def encode_point(self, point, compressed=False):
        ...

    @abc.abstractmethod
    def decode_point(self, byte_data):
        ...

    def bit_size(self):
        return self.group.n.bit_length()

    def byte_size(self):
        return (self.bit_size() + 7) // 8

    @abc.abstractmethod
    def field_size(self):
        ...

    def __eq__(self, other):
        if not isinstance(other, Curve):
            return False
        return self.field == other.field and self.a == other.a and self.b == other.b and self.group == other.group

    def __repr__(self):
        return str(self)


class CurveFp(Curve):
    def is_singular(self):
        return (4 * self.a ** 3 + 27 * self.b ** 2) == 0

    def on_curve(self, x, y):
        return (y ** 2 - x ** 3 - self.a * x - self.b) == 0

    def add(self, x1, y1, x2, y2):
        lm = (y2 - y1) / (x2 - x1)
        x3 = lm ** 2 - x1 - x2
        y3 = lm * (x1 - x3) - y1
        return x3, y3

    def dbl(self, x, y):
        lm = (3 * x ** 2 + self.a) / (2 * y)
        x3 = lm ** 2 - (2 * x)
        y3 = lm * (x - x3) - y
        return x3, y3

    def mul(self, k, x, y, z=1):
        def _add(x1, y1, z1, x2, y2, z2):
            yz = y1 * z2
            xz = x1 * z2
            zz = z1 * z2
            u = y2 * z1 - yz
            uu = u ** 2
            v = x2 * z1 - xz
            vv = v ** 2
            vvv = v * vv
            r = vv * xz
            a = uu * zz - vvv - 2 * r
            x3 = v * a
            y3 = u * (r - a) - vvv * yz
            z3 = vvv * zz
            return x3, y3, z3

        def _dbl(x1, y1, z1):
            xx = x1 ** 2
            zz = z1 ** 2
            w = self.a * zz + 3 * xx
            s = 2 * y1 * z1
            ss = s ** 2
            sss = s * ss
            r = y1 * s
            rr = r ** 2
            b = (x1 + r) ** 2 - xx - rr
            h = w ** 2 - 2 * b
            x3 = h * s
            y3 = w * (b - h) - 2 * rr
            z3 = sss
            return x3, y3, z3
        r0 = (x, y, z)
        r1 = _dbl(x, y, z)
        for i in range(k.bit_length() - 2, -1, -1):
            if k & (1 << i):
                r0 = _add(*r0, *r1)
                r1 = _dbl(*r1)
            else:
                r1 = _add(*r0, *r1)
                r0 = _dbl(*r0)
        rx, ry, rz = r0
        rzi = ~rz
        return rx * rzi, ry * rzi

    def neg(self, x, y):
        return x, -y

    def field_size(self):
        return self.field.bit_length()

    def encode_point(self, point, compressed=False):
        byte_size = (self.field_size() + 7) // 8
        if not compressed:
            return bytes((0x04,)) + int(point.x).to_bytes(byte_size, byteorder="big") + int(
                    point.y).to_bytes(byte_size, byteorder="big")
        else:
            yp = int(point.y) & 1
            pc = bytes((0x02 | yp,))
            return pc + int(point.x).to_bytes(byte_size, byteorder="big")

    def decode_point(self, byte_data):
        if byte_data[0] == 0 and len(byte_data) == 1:
            return Inf(self)
        byte_size = (self.field_size() + 7) // 8
        if byte_data[0] in (0x04, 0x06):
            if len(byte_data) != 1 + byte_size * 2:
                raise ValueError
            x = Mod(int.from_bytes(byte_data[1:byte_size + 1], byteorder="big"), self.field)
            y = Mod(int.from_bytes(byte_data[byte_size + 1:], byteorder="big"), self.field)
            return Point(self, x, y)
        elif byte_data[0] in (0x02, 0x03):
            if len(byte_data) != 1 + byte_size:
                raise ValueError
            x = Mod(int.from_bytes(byte_data[1:byte_size + 1], byteorder="big"), self.field)
            rhs = x ** 3 + self.a * x + self.b
            sqrt = rhs.sqrt()
            yp = byte_data[0] & 1
            if int(sqrt) & 1 == yp:
                return Point(self, x, sqrt)
            else:
                return Point(self, x, self.field - sqrt)
        raise ValueError

    def __str__(self):
        return "\"{}\": y^2 = x^3 + {}x + {} over {}".format(self.name, self.a, self.b, self.field)


class CurveF2m(Curve):
    def is_singular(self):
        return self.b == 0

    def on_curve(self, x, y):
        return (y ** 2 + x * y - x ** 3 - self.a * x ^ 2 - self.b) == 0

    def add(self, x1, y1, x2, y2):
        lm = (y1 + y2) / (x1 + x2)
        x3 = lm ** 2 + lm + x1 + x2 + self.a
        y3 = lm * (x1 + x3) + x3 + y1
        return x3, y3

    def dbl(self, x, y):
        lm = x + y / x
        x3 = lm ** 2 + lm + self.a
        y3 = x ** 2 + lm * x3 + x3
        return x3, y3

    def mul(self, k, x, y, z=1):
        def _add(x1, y1, z1, x2, y2, z2):
            a = x1 * z2
            b = x2 * z1
            c = a ** 2
            d = b ** 2
            e = a + b
            f = c + d
            g = y1 * (z2 ** 2)
            h = y2 * (z1 ** 2)
            i = g + h
            j = i * e
            z3 = f * z1 * z2
            x3 = a * (h + d) + b * (c + g)
            y3 = (a * j + f * g) * f + (j + z3) * x3
            return x3, y3, z3

        def _dbl(x1, y1, z1):
            a = x1 * z1
            b = x1 * x1
            c = b + y1
            d = a * c
            z3 = a * a
            x3 = c ** 2 + d + self.a * z3
            y3 = (z3 + d) * x3 + b ** 2 * z3
            return x3, y3, z3
        r0 = (x, y, z)
        r1 = _dbl(x, y, z)
        for i in range(k.bit_length() - 2, -1, -1):
            if k & (1 << i):
                r0 = _add(*r0, *r1)
                r1 = _dbl(*r1)
            else:
                r1 = _add(*r0, *r1)
                r0 = _dbl(*r0)
        rx, ry, rz = r0
        rzi = ~rz
        return rx * rzi, ry * (rzi ** 2)

    def neg(self, x, y):
        return x, x + y

    def field_size(self):
        return self.field.n

    def encode_point(self, point, compressed=False):
        byte_size = (self.field_size() + 7) // 8
        if not compressed:
            return bytes((0x04,)) + int(point.x).to_bytes(byte_size, byteorder="big") + int(
                    point.y).to_bytes(byte_size, byteorder="big")
        else:
            if int(point.x) == 0:
                yp = 0
            else:
                yp = int(point.y * point.x.inverse())
            pc = bytes((0x02 | yp,))
            return pc + int(point.x).to_bytes(byte_size, byteorder="big")

    def decode_point(self, byte_data):
        if byte_data[0] == 0 and len(byte_data) == 1:
            return Inf(self)
        byte_size = (self.field_size() + 7) // 8
        if byte_data[0] in (0x04, 0x06):
            if len(byte_data) != 1 + byte_size * 2:
                raise ValueError
            x = FElement(int.from_bytes(byte_data[1:byte_size + 1], byteorder="big"), self.field)
            y = FElement(int.from_bytes(byte_data[byte_size + 1:], byteorder="big"), self.field)
            return Point(self, x, y)
        elif byte_data[0] in (0x02, 0x03):
            if self.field.n % 2 != 1:
                raise NotImplementedError
            x = FElement(int.from_bytes(byte_data[1:byte_size + 1], byteorder="big"), self.field)
            yp = byte_data[0] & 1
            if int(x) == 0:
                y = self.b ** (2 ** (self.field.n - 1))
            else:
                rhs = x + self.a + self.b * x ** (-2)
                z = rhs.half_trace()
                if z ** 2 + z != rhs:
                    raise ValueError
                if int(z) & 1 != yp:
                    z += 1
                y = x * z
            return Point(self, x, y)
        raise ValueError

    def __str__(self):
        return "\"{}\" => y^2 + xy = x^3 + {}x^2 + {} over {}".format(self.name, self.a, self.b,
                                                                      self.field)


class SubGroup(object):
    def __init__(self, g, n, h):
        self.g = g
        self.n = n
        self.h = h

    def __eq__(self, other):
        if not isinstance(other, SubGroup):
            return False
        return self.g == other.g and self.n == other.n and self.h == other.h

    def __str__(self):
        return "Subgroup => generator {}, order: {}, cofactor: {}".format(self.g, self.n, self.h)

    def __repr__(self):
        return str(self)


class Inf(object):
    def __init__(self, curve, x=None, y=None):
        self.x = x
        self.y = y
        self.curve = curve

    def __eq__(self, other):
        if not isinstance(other, Inf):
            return False
        return self.curve == other.curve

    def __ne__(self, other):
        return not self.__eq__(other)

    def __neg__(self):
        return self

    def __add__(self, other):
        if isinstance(other, Inf):
            return Inf(self.curve)
        if isinstance(other, Point):
            return other
        raise TypeError(
                "Unsupported operand type(s) for +: '%s' and '%s'" % (self.__class__.__name__,
                                                                      other.__class__.__name__))

    def __radd__(self, other):
        return self + other

    def __sub__(self, other):
        if isinstance(other, Inf):
            return Inf(self.curve)
        if isinstance(other, Point):
            return other
        raise TypeError(
                "Unsupported operand type(s) for +: '%s' and '%s'" % (self.__class__.__name__,
                                                                      other.__class__.__name__))

    def __str__(self):
        return "{} on {}".format(self.__class__.__name__, self.curve)

    def __repr__(self):
        return str(self)


class Point(object):
    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y

    def __eq__(self, other):
        if not isinstance(other, Point):
            return False
        return self.x == other.x and self.y == other.y and self.curve == other.curve

    def __ne__(self, other):
        return not self.__eq__(other)

    def __neg__(self):
        return Point(self.curve, *self.curve.neg(self.x, self.y))

    def __add__(self, other):
        if isinstance(other, Inf):
            return self
        if isinstance(other, Point):
            if self.curve != other.curve:
                raise ValueError("Cannot add points belonging to different curves")
            if self == -other:
                return Inf(self.curve)
            elif self == other:
                return Point(self.curve, *self.curve.dbl(self.x, self.y))
            else:
                return Point(self.curve, *self.curve.add(self.x, self.y, other.x, other.y))
        else:
            raise TypeError(
                    "Unsupported operand type(s) for +: '{}' and '{}'".format(
                            self.__class__.__name__,
                            other.__class__.__name__))

    def __radd__(self, other):
        return self + other

    def __sub__(self, other):
        return self + (-other)

    def __rsub__(self, other):
        return self - other

    def __mul__(self, other):
        if isinstance(other, int):
            if other % self.curve.group.n == 0:
                return Inf(self.curve)
            if other < 0:
                other = -other
                addend = -self
            else:
                addend = self
            if hasattr(self.curve, "mul") and callable(getattr(self.curve, "mul")):
                return Point(self.curve, *self.curve.mul(other, addend.x, addend.y))
            else:
                result = Inf(self.curve)
                # Iterate over all bits starting by the LSB
                for bit in reversed([int(i) for i in bin(abs(other))[2:]]):
                    if bit == 1:
                        result += addend
                    addend += addend
                return result
        else:
            raise TypeError(
                    "Unsupported operand type(s) for *: '%s' and '%s'" % (other.__class__.__name__,
                                                                          self.__class__.__name__))

    def __rmul__(self, other):
        return self * other

    def __str__(self):
        return "({}, {}) on {}".format(self.x, self.y, self.curve)

    def __repr__(self):
        return str(self)


def load_curve(file, name=None):
    data = file.read()
    parts = list(map(lambda x: int(x, 16), data.split(",")))
    if len(parts) == 7:
        p, a, b, gx, gy, n, h = parts
        g = (Mod(gx, p), Mod(gy, p))
        group = SubGroup(g, n, h)
        return CurveFp(p, Mod(a, p), Mod(b, p), group, name)
    elif len(parts) == 10:
        m, e1, e2, e3, a, b, gx, gy, n, h = parts
        poly = [m, e1, e2, e3, 0]
        field = FField(m, poly)
        g = (FElement(gx, field), FElement(gy, field))
        group = SubGroup(g, n, h)
        return CurveF2m(field, FElement(a, field), FElement(b, field), group, name)
    else:
        raise ValueError("Invalid curve data")


def get_curve(idd):
    cat, i = idd.split("/")
    with open(path.join("..", "src", "cz", "crcs", "ectester", "data", cat, i + ".csv"), "r") as f:
        return load_curve(f, i)

