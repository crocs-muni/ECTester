# Implementations

This document contains information about possible implementation choices and algorithms when implementing elliptic curve cryptography. It is mainly concerned with curve models, coordinate systems, addition formulas and scalar multiplication algorithms. Also, only curves over \( \mathbb{F}_p \) are analyzed.

---

## Curve models

### Weierstrass (full)

#### Affine
$$ y^2 + a_1xy + a_3y = x^3 + a_2x^2 + a_4x + a_6 $$

#### Projective
$$ Y^2Z + a_1XYZ + a_3YZ^2 = X^3 + a_2X^2Z + a_4XZ^2 + a_6Z^3 $$


### Weierstrass (short)

[EFD entry](https://www.hyperelliptic.org/EFD/g1p/auto-shortw.html)

    toweierstrass weierx = x
    toweierstrass weiery = y
    a0 = 1
    a1 = 0
    a2 = 0
    a3 = 0
    a4 = a
    a6 = b
    fromweierstrass x = weierx
    fromweierstrass y = weiery

#### Affine
$$ y^2 = x^3 + a x + b $$

#### Projective
$$ Y^2Z = X^3 + aXZ^2 + bZ^3 $$

#### Jacobian
$$ Y^2 = X^3 + aXZ^4 + bZ^6 $$


### Montgomery

[EFD entry](https://www.hyperelliptic.org/EFD/g1p/auto-montgom.html)

    toweierstrass weierx = x
    toweierstrass weiery = y
    a0 = b
    a1 = 0
    a2 = a
    a3 = 0
    a4 = 1
    a6 = 0
    fromweierstrass x = weierx
    fromweierstrass y = weiery

#### Affine
$$ By^2 = x^3 + Ax^2 + x $$


### Edwards

[EFD entry](https://www.hyperelliptic.org/EFD/g1p/auto-edwards.html)

    toweierstrass u = (c+y)/(c-y)
    toweierstrass v = 2 c (c+y)/(x(c-y))
    a0 = 1/(1-d c^4)
    a1 = 0
    a2 = 4/(1-d c^4)-2
    a3 = 0
    a4 = 1
    a6 = 0
    fromweierstrass x = 2 c u/v
    fromweierstrass y = c(u-1)/(u+1)

#### Affine
$$ x^2 + y^2 = c^2 (1 + dx^2y^2) $$


### Twisted Edwards

[EFD entry](https://www.hyperelliptic.org/EFD/g1p/auto-twisted.html)

    toweierstrass u = (1+y)/(1-y)
    toweierstrass v = 2 (1+y)/(x(1-y))
    a0 = 1/(a-d)
    a1 = 0
    a2 = 4 a/(a-d)-2
    a3 = 0
    a4 = 1
    a6 = 0
    fromweierstrass x = 2 u/v
    fromweierstrass y = (u-1)/(u+1)

#### Affine
$$ ax^2 + y^2=1 + dx^2y^2 $$


### Hessian

[EFD entry](https://www.hyperelliptic.org/EFD/g1p/auto-hessian.html)

    toweierstrass u = 12(d^3-1)/(d+x+y)-9 d^2
    toweierstrass v = 36(y-x)(d^3-1)/(d+x+y)
    a0 = 1
    a1 = 0
    a2 = 0
    a3 = 0
    a4 = -27 d(d^3+8)
    a6 = 54(d^6-20 d^3-8)
    fromweierstrass x = (36(d^3-1)-v)/(6(u+9 d^2))-d/2
    fromweierstrass y = (v+36(d^3-1))/(6(u+9 d^2))-d/2

#### Affine
$$ x^3+y^3+1=3dxy $$

#### Projective
$$ X^3 + Y^3 + Z^3 = 3dXYZ $$


---

## Coordinates

### Affine

$$ [x, y] \in \mathbb{K}^2 $$

*(Weierstrass)* infinity is special cased, sometimes represented as \( [0] \).

*(Weierstrass)* negation: \(-[x, y] = [x, -y] \)

 - To Projective: \( [x, y] \rightarrow (x : y : 1) \)
 - To Jacobian: \( [x, y] \rightarrow (x : y : 1) \)
 - To Chudnovsky: \( [x, y] \rightarrow (x : y : 1 : 1 : 1) \)

### Projective
\begin{align*}
[X, Y, Z] &\in \mathbb{K}^3 \\
[X_1, Y_1, Z_1] &\sim [X_2, Y_2, Z_2] \\
\text{if}\ X_1 &= λ X_2, \\
   Y_1 &= λ Y_2, \\
   Z_1 &= λ Z_2 \\
\text{for some}\ λ &\in \mathbb{K}^* \\
(X : Y : Z) &= \{(λ X, λ Y, λ Z) | λ \in \mathbb{K}^* \}
\end{align*}

*(Weierstrass)* infinity is \((0 : 1 : 0)\).

*(Weierstrass)* negation: \( -(X : Y : Z) = (X : -Y : Z) \)

 - To Affine: \( (X : Y : Z) \rightarrow [X/Z, Y/Z] \)
 - To Jacobian: \( (X : Y : Z) \rightarrow (X/Z : Y/Z : 1) \) ?
 - To Chudnovsky: \( (X : Y : Z) \rightarrow (X/Z : Y/Z : 1 : 1 : 1) \) ?

### Jacobian
\begin{align*}
[X, Y, Z] &\in \mathbb{K}^3 \\
[X_1, Y_1, Z_1] &\sim [X_2, Y_2, Z_2] \\
\text{if}\ X_1 &= λ^2 X_2, \\
   Y_1 &= λ^3 Y_2, \\
   Z_1 &= λ Z_2 \\
\text{for some}\ λ &\in \mathbb{K}^* \\
(X : Y : Z) &= \{(λ^2 X, λ^3 Y, λ Z) | λ \in \mathbb{K}^* \}
\end{align*}

*(Weierstrass)* infinity is \( (1 : 1 : 0) \).

*(Weierstrass)* negation: \( -(X : Y : Z) = (X : -Y : Z) \)

 - To Affine: \( (X : Y : Z) \rightarrow [X/Z^2, Y/Z^3] \)
 - To Projective: \( (X : Y : Z) \rightarrow (X/Z^2 : Y/Z^3 : 1) \) ?
 - To Chudnovsky: \( (X : Y : Z) \rightarrow (X : Y : Z : Z^2 : Z^3) \)

### Chudnovsky
\begin{align*}
[X, Y, Z, Z^2, Z^3] &\in \mathbb{K}^5 \\
(X : Y : Z : Z^2 : Z^3 ) &= \{(λ^2 X, λ^3 Y, λ Z, λ^2 Z^2, λ^3 Z^3) | λ \in \mathbb{K}^* \}
\end{align*}

*(Weierstrass)* infinity is \( (1 : 1 : 0 : 0 : 0) \). ?

*(Weierstrass)* negation: \( -(X : Y : Z : Z^2 : Z^3) = (X : -Y : Z : Z^2 : Z^3) \)

 - To Affine: \( (X : Y : Z : Z^2 : Z^3) \rightarrow [X/Z^2, Y/Z^3] \)
 - To Projective: \( (X : Y : Z : Z^2 : Z^3) \rightarrow (X/Z^2 : Y/Z^3 : 1) \) ?
 - To Jacobian: \( (X : Y : Z : Z^2 : Z^3) \rightarrow (X : Y : Z) \)


---

## Formulas

 - Addition
 - Doubling
 - Tripling
 - Differential addition
 - Differential addition and doubling
 - Scaling

See EFD[^3].

---

## Scalar multiplication

See TAOCP volume 2, section 4.6.3 for introduction to multiplication/exponentiation and addition/multiplication chains.[^5]

Scalar multiplication on elliptic curves is very similar to usual multiplication/exponentiation in general additive/multiplicative groups, respectively, with some additional structure:

 - \(A + B\) when \(A \ne B\) might be a different operation from \(A + A = [2]A\), and also sometimes takes different time.
 - negation \(-A\) is easy/fast.
 - \(0\) sometimes has a special representation and thus requires special casing.
 - sometimes, there exists a fast operation of \(\phi: E(\mathbb{F}_p) \rightarrow E(\mathbb{F}_p) \) with \( \phi(P) = [k]P \) for some \(k \in \mathbb{K}\) computable using some endomorphism on the curve.

Some links:

 - [wiki/Addition_chain](https://en.wikipedia.org/wiki/Addition_chain)
 - [wiki/Addition-subtraction_chain](https://en.wikipedia.org/wiki/Addition-subtraction_chain)
 - [wiki/Exponentiation_by_squaring](https://en.wikipedia.org/wiki/Exponentiation_by_squaring)
 - [wiki/Addition-chain_exponentiation](https://en.wikipedia.org/wiki/Addition-chain_exponentiation)

We define:

 - \( \lambda(k) = \lfloor \log_2 k \rfloor \) , the size of k
 - \( k_i \) , the *i*-th bit of *k*
 - \( \nu(k) = \vert \{ i \vert 0 \le i \le \lambda(k), k_i = 1\} \vert \) , the number of nonzero bits in *k*
 - \( l(k) \) , the length of NAF of *k*
 - \( \sigma(k) = \vert \{ i \vert 0 \le i \le l(k), NAF(k)_i \ne 0 \} \vert \) , the number of nonzero values in the NAF of *k*
 - \( C_2 \) , the cost of doubling a point
 - \( C_+ \) , the cost of point addition
 - \( C_{algo}(k) \) , the cost of scalar multiplication by *k* of the algorithm *algo*
 - *Addition chain* of *n*, is a sequence of integers:
\( 1 = a_0, a_1, \ldots, a_r = n\),
where \(a_i = a_j + a_k\) for some \( k \le j < i, \forall i \in \{ 1, 2, \ldots, r \} \)
 - *Addition-subtraction chain* of *n*, is a sequence of integers:
\( 1 = a_0, a_1, \ldots, a_r = n\),
where \(a_i = \pm a_j \pm a_k\) for some \( k \le j < i, \forall i \in \{ 1, 2, \ldots, r \} \)
 - *Addition sequence* for \( r_1, r_2, \ldots, r_t \) is an addition chain: \( 1 = a_1, a_2, \ldots, a_l \) which contains \( r_1, r_2, \ldots, r_t \). Useful when operating with one element and many powers \( g^{r_1}, g^{r_2}, \ldots \)
 - *Vector addition chain* for \(r \in \mathbb{N}^t \) is a sequence of elements \( v_i \) of \( \mathbb{N}^t \) such that \( v_i = e_i \) for \( 1 \le i \le t \) and  \( v_i = v_j + v_k \) for \(j \le k < i \). Useful when powering many elements to many powers \( g_1^{r_1}, g_2^{r_2}, \ldots \)

### Double and Add (binary exponentiation)

Uses binary addition chain.

<u>Algorithm 3.26</u> (right-to-left) in GECC[^1]

    INPUT: k = (k_{t-1}, ..., k_1, k_0)_2, P ∈ E(F_q).
    OUTPUT: [k]P.
    1. Q ← ∞.
    2. For i from 0 to t-1 do
    2.1 If k_i = 1 then Q ← Q + P.
    2.2 P ← 2P.
    3. Return(Q).

<u>Algorithm 3.27</u> (left-to-right) in GECC[^1]

    INPUT: k = (k_{t-1}, ..., k_1, k_0)_2, P ∈ E(F_q).
    OUTPUT: [k]P.
    1. Q ← ∞.
    2. For i from t - 1 downto 0 do
    2.1 Q ← 2Q.
    2.2 If k_i = 1 then Q ← Q + P.
    3. Return(Q).

Cost: \( C_{binexp}(k) = \lambda(k)C_2 + (\nu(k) - k_0)C_+\)[^7]

### Double and Add Always (binary exponentiation - constant time)

Uses binary addition chain, but does all the additions/multiplications.

(right-to-left)

    INPUT: k = (k_{t-1}, ..., k_1, k_0)_2, P ∈ E(F_q).
    OUTPUT: [k]P.
    1. Q ← ∞.
    2. For i from t - 1 downto 0 do
    2.1 If k_i = 1 then Q ← Q + P else Dummy ← Q + P.
    2.2 P ← 2P.
    3. Return(Q).

(left-to-right)

    INPUT: k = (k_{t-1}, ..., k_1, k_0)_2, P ∈ E(F_q).
    OUTPUT: [k]P.
    1. Q ← ∞.
    2. For i from t - 1 downto 0 do
    2.1 Q ← 2Q.
    2.2 If k_i = 1 then Q ← Q + P else Dummy ← Q + P.
    3. Return(Q).

Cost: \( C_{const\_binexp}(k) = \lambda(k) (C_2 + C_+) \) ?


### Binary NAF multiplication (signed binary exponentiation)

**Definition 3.28**[^1] A *non-adjacent form (NAF)* of a positive integer *k* is an expression \( k = \Sigma_{i=0}^{l - 1} k_i 2^i \) where \(k_i \in \{0, ±1\}, k_{l−1} \ne 0\), and no two consecutive digits \( k_i \) are nonzero. The length of the NAF is *l*.

<u>Algorithm 3.30</u> Computing the NAF of a positive integer[^1]

    INPUT: A positive integer k.
    OUTPUT: NAF(k).
    1. i ← 0.
    2. While k ≥ 1 do
    2.1 If k is odd then:
            k_i ← 2 − (k mod 4), k ← k − k_i ;
    2.2 Else:
            k_i ← 0.
    2.3 k ← k/2, i ← i + 1.
    3. Return(k_{i−1}, k_{i−2}, ..., k_1, k_0).

<u>Algorithm 3.31</u> Binary NAF multiplication (left-to-right)[^1]

    INPUT: Positive integer k, P ∈ E(F_q).
    OUTPUT: [k]P.
    1. Use Algorithm 3.30 to compute NAF(k).
    2. Q ← ∞.
    3. For i from l - 1 downto 0 do
    3.1 Q ← 2Q.
    3.2 If k_i = 1 then Q ← Q + P.
    3.3 If k_i = -1 then Q ← Q - P.
    4. Return(Q).

Can be made constant time.

Cost: \( C_{bin\_NAF} = l(k)C_2 + \sigma(k)C_+ + \text{NAF computation cost}\) ?

### \(m\)-ary method

Like binary double-and-add but uses a different base *m*.[^6]

    INPUT: k = (k_{t-1}, ..., k_1, k_0)_m, P ∈ E(F_q).
    OUTPUT: [k]P
    1. Compute P_i = [i]P for i ∈ {1, 2, ..., m - 1}.
    2. Q ← ∞.
    3. For i from l downto 0 do
    3.1 Q ← [m]Q.
    3.2 Q ← Q + P_{k_i}.
    4. Return(Q).

### \( 2^r \) method

Like \(m\)-ary method, with \( m = 2^r \), means that `[m]Q` is doable with only doubling.[^6]

### Sliding window

<u>Algorithm 13.6</u> Sliding window in HEHCC[^2]

    INPUT: Window width w, k = (k_{t-1}, ..., k_1, k_0)_2, P ∈ E(F_q).
    OUTPUT: [k]P
    1. Compute P_i = [i]P for i ∈ {3, 5, ..., 2^w - 1}. //precomputation for fixed P
    2. Q ← ∞, i ← t - 1.
    3. While i ≥ 0 do
    3.1 If k_i = 0 then:
            Q ← [2]Q, i ← i - 1.
    3.2 Else:
    3.2.1   s ← max(i - k + 1, 0).
    3.2.2   While k_s = 0 do
                s ← s + 1.
    3.2.3   For h from 1 to i - s + 1 do
                Q ← [2]Q.
    3.2.4   u ← (k_i, ..., k_s)_2.
    3.2.5   Q ← P_u.                // u is odd.
    3.2.6   i ← s - 1.
    4. Return(Q).

<u>Algorithm 3.38</u> Sliding window with NAF(signed sliding window) in GECC[^1]

    INPUT: Window width w, positive integer k, P ∈ E(F_q).
    OUTPUT: [k]P.
    1. Use Algorithm 3.30 to compute NAF(k).
    2. Compute P_i = [i]P for i ∈ {1, 3, ..., 2(2^w - (-1)^w)/3 - 1}. //precomputation for fixed P
    3. Q ← ∞, i ← l - 1.
    4. While i ≥ 0 do
    4.1 If k_i = 0 then:
            t ← 1, u ← 0.
    4.2 Else:
            find the largest t ≤ w such that u ← (k_i , ..., k_{i-t+1}) is odd.
    4.3 Q ← [2^t]Q.
    4.4 If u > 0 then:
            Q ← Q + P_u.
    4.5 Else:
            if u < 0 then Q ← Q - P_{-u}.
    4.6 i ← i - t.
    5. Return(Q).

### Window NAF multiplication

**Definition 3.32**[^1] Let \( w \ge 2 \) be a positive integer. A *width-w NAF* of a positive integer *k* is an expression \( k = \Sigma_{i=0}^{l - 1} k_i 2^i \) where each nonzero coefficient \( k_i \) is odd, \( \vert k_i \vert < 2^{w - 1}, k_{l-1} \ne 0 \), and at most one of any *w* consecutive digits is nonzero. The length of the width-w NAF is *l*.


<u>Algorithm 3.35</u> Computing the width-w NAF of a positive integer[^1]

    INPUT : Window width w, positive integer k.
    OUTPUT : NAF-w(k).
    1. i ← 0.
    2. While k ≥ 1 do
    2.1 If k is odd then:
            k_i ← k mods 2^w , k ← k − k_i; // k mods 2^w is an integer u, -2^{w-1} ≤ u < 2^{w-1}, u ≡ k mod 2^w
    2.2 Else:
            k_i ← 0.
    2.3 k ← k/2, i ← i + 1.
    3. Return(k_{i−1}, k_{i−2}, ..., k_1, k_0).

<u>Algorithm 3.36</u> in GECC[^1]

    INPUT: Window width w, positive integer k, P ∈ E(F_q).
    OUTPUT: [k]P.
    1. Use Algorithm 3.35 to compute NAF-w(k).
    2. Compute P_i = [i]P for i ∈ {1, 3, 5, ..., 2^{w-1} - 1}. //precomputation for fixed P
    3. Q ← ∞.
    4. For i from l - 1 downto 0 do
    4.1 Q ← 2Q.
    4.2 If k_i != 0 then:
            If k_i > 0 then:
                Q ← Q + P_{k_i} ;
            Else:
                Q ← Q - P_{-k_i} .
    5. Return(Q).

### Fractional window

[^10] and [^11]

### Montgomery ladder

The same name, Montgomery ladder, is used both for the general ladder idea of exponentiation/scalar-multiplication and the concrete *x*-coordinate only addition formulas and scalar multiplication algorithm on Montgomery curves.

<u>Algorithm 13.35</u> in [^2] (general Montgomery ladder)

    INPUT: k = (k_{t-1}, ..., k_1, k_0)_2, P ∈ E(F_q).
    OUTPUT: [k]P .
    1. P_1 ← P and P_2 ← [2]P
    2. For i = t − 1 downto 0 do
    2.1 If k_i = 0 then
             P_1 ← [2]P_1; P_2 ← P_1 + P_2.
        Else
             P_1 ← P_1 + P_2; P_2 ← [2]P_2.
    3. Return(P_1).

<u>Algorithm 3.</u> in [^8] (general Montgomery ladder)

    INPUT: G ∈ E(F_q), k = (1, k_{t−2}, ..., k_0)2
    OUTPUT: Y = kG
    1. R0 ← G; R1 ← [2]G
    2. for j = t − 2 downto 0 do
    2.1  if (k_j = 0) then
             R1 ← R0 + R1; R0 ← [2]R0
         else [if (kj = 1)]
             R0 ← R0 + R1; R1 ← [2]R1
    3. return R0

Montgomery addition formulas (Projective coordinates/XZ coordinates):[^2]

 - Addition (\( n \ne m \)):
\begin{align*}
X_{m+n} &= Z_{m-n}((X_m - Z_m)(X_n + Z_n) + (X_m + Z_m)(X_n - Z_n))^2 \\
Z_{m+n} &= X_{m-n}((X_m - Z_m)(X_n + Z_n) - (X_m + Z_m)(X_n - Z_n))^2
\end{align*}

 - Doubling:
\begin{align*}
4X_nZ_n &= (X_n + Z_n)^2 - (X_n - Z_n)^2 \\
X_{2n} &= (X_n + Z_n)^2 (X_n - Z_n)^2 \\
Z_{2n} &= 4X_nZ_n((X_n - Z_n)^2 + ((A + 2)/4)(4X_nZ_n))
\end{align*}

 - \( Y \) recovery:
\begin{align*}
x_n &= X_n / Z_n; \qquad x_{n+1} = X_{n+1} / Z_{n+1} \\
y_n &= \frac{(x_1x_n + 1) (x_1 + x_n + 2A) - 2A - (x_1 - x_n)^2x_{n+1}}{2By_1}
\end{align*}

### Brier-Joye (+ Lopez-Dahab) ladder

Not really a scalar-multiplication algorithm. Generalization of the stricter Montgomery ladder(the *x*-coordinate only scalar-mult algo and addition formulas on Montgomery curves) to short Weierstrass elliptic curves over fields of \( \text{char}\ \mathbb{K} \ne 2, 3 \) by Brier & Joye. Furthermore the *x*-coordinate only addition formulas were generalized to curves over \( \mathbb{F}_{2^m} \) by Lopez & Dahab.

Brier-Joye addition formulas (Projective coordinates/XZ coordinates):[^2]

 - Addition (\( n \ne m \)):
\begin{align*}
X_{m+n} &= Z_{m-n}(-4a_6Z_mZ_n(X_mZ_n + X_nZ_m) + (X_mX_n - a_4 Z_mZ_n)^2) \\
Z_{m+n} &= X_{m-n}(X_mZ_n - X_nZ_m)^2
\end{align*}

 - Doubling:
\begin{align*}
X_{2n} &= (X_n^2 - a_4Z_n^2)^2 - 8 a_6X_nZ_n^3 \\
Z_{2n} &= 4Z_n(X_n(X_n^2 + a_4 Z_n^2) + a_6Z_n^3)
\end{align*}

 - \( Y \) recovery:
\begin{align*}
x_n &= X_n / Z_n; \qquad x_{n+1} = X_{n+1} / Z_{n+1} \\
y_n &= \frac{2a_6 +(x_1x_n + a_4) (x_1 + x_n) - (x_1 - x_n)^2x_{n+1}}{2y_1}
\end{align*}

Lopez-Dahab addition formulas on \( E(\mathbb{F}_{2^m}) \)(Projective coordinates/XZ coordinates):[^2]

 - Addition (\( n \ne m \)):
\begin{align*}
Z_{m+n} &= (X_mZ_n)^2 + (X_nZ_m)^2 \\
X_{m+n} &= Z_{m+n}X_{m-n} + X_mZ_nX_nZ_m
\end{align*}

 - Doubling:
\begin{align*}
X_{2n} &= X_n^4 + a_6Z_n^4 = (X_n^2 + \sqrt{a_6}Z_n^2)^2 \\
Z_{2n} &= X_n^2Z_n^2
\end{align*}

 - \( Y \) recovery:
\begin{align*}
x_n &= X_n / Z_n; \qquad x_{n+1} = X_{n+1} / Z_{n+1} \\
y_n &= \frac{(x_n + x_1)((x_n + x_1)(x_{n+1} + x_1) + x_1^2 + y_1)}{x_1} + y_1
\end{align*}

### GLV scalar multiplication

[^13]

### Fixed-base windowing (BGMW)

<u>Algorithm 3.41</u> and <u>Algorithm 3.42</u> in GECC[^1]


### Fixed-base comb

<u>Algorithm 3.44</u> and <u>Algorithm 3.45</u> in GECC[^1]

### Möller-1

> The method may fail in some cases in that an addition step may turn out to be a point doubling or may involve the point at infinity (which both requires special treatment and is potentially clearly visible through side channels). However, we will show that the probability of this happening is negligible if multipliers are appropriately selected: Randomly chosen e is safe.[^9]

## References

[^1]: HANKERSON, Darrel; MENEZES, Alfred J.; VANSTONE, Scott. Guide to Elliptic Curve Cryptography. New York, USA: Springer, 2004. ISBN 9780387218465. Available from DOI: [10.1007/b97644](https://dx.doi.org/10.1007/b97644).

[^2]: COHEN, Henri; FREY, Gerhard; AVANZI, Roberto M.; DOCHE, Christophe; LANGE, Tanja; NGUYEN, Kim; VERCAUTEREN, Frederik. Handbook of Elliptic and Hyper-elliptic Curve Cryptography. CRC Press, 2005-07-19. Discrete Mathematics and It’s Applications, no. 34. ISBN 9781584885184.

[^3]: BERNSTEIN, Daniel J.; LANGE, Tanja. Explicit Formulas Database, <https://www.hyperelliptic.org/EFD/>

[^4]: <http://point-at-infinity.org/ecc/>

[^5]: KNUTH, Donald: The Art of Computer Programming, Volume 2: Seminumerical algorithms

[^6]: GORDON, Daniel M.: A survey of fast exponentiation methods.

[^7]: MORAIN, Francois; OLIVOS, Jorge: Speeding up the computations on an elliptic curve using addition-subtraction chains.

[^8]: JOYE, Marc; YEN, Sung-Ming: The Montgomery Powering Ladder.

[^9]: MOLLER, Bodo: Securing Elliptic Curve Point Multiplication against Side-Channel Attacks.

[^10]: MOLLER, Bodo: Improved Techniques for Fast Exponentiation.

[^11]: MOLLER, Bodo: Fractional Windows Revisited: Improved Signed-Digit Representations for Efficient Exponentiation.

[^12]: KOYAMA, Kenji; TSURUOKA, Yukio: Speeding up Elliptic Cryptosystems by Using a Signed Binary Window Method.

[^13]: GALLANT, Robert P.; LAMBERT, Robert J.; VANSTONE, Scott A.: Faster point multiplication on elliptic curves with efficient endomorphisms.