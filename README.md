---
title: LumoSQL ABE-SSS
author: Martina Palmucci
date: \today
---

## Introduction
LumoSQL is an ambitious project that aims to bring encrypted storage modes to SQLite embedded databases, while keeping the standard SQL-GRANT syntax. In this context, encryption is one of the major problems. LumoSQL not only strives for data confidentiality, but also for more fine-grained data protection. It aspires to be able to encrypt the whole database as well as single tables or columns. The above said contributes to support the ambitious nature of this objective and the complexity of the issues involved. In fact, current solutions only offer a full encryption database with a unique key.

The Attribute-Based Encryption-Shamir's Secret Sharing (ABE-SSS), an encryption system capable of achieving the above objectives, is part of the LumoSQL project.

## ABE-SSS

ABE-SSS, as the term suggests, combines two distinct techniques to produce a single powerful solution.

Attribute-Based Encryption is an asymmetric cryptographic primitive in which the ciphertext and the user's secret key are both determined by attributes. Only if the set of attributes of the user key matches the attributes of the ciphertext can a ciphertext be decrypted in such a system. Since LumoSQL intends retaining GRANT-style syntax, Attribute-Based Encryption perfectly maps GRANT-style privileges.

Shamir's Secret Sharing is one of the first cryptographic secret sharing techniques. It allows to split a secret number $s$ into $n$ shares and, given a threshold $t < n$ of shares, we can reconstruct $s$. Shamir's Secret Sharing can be also classified as a $(t, n)$-threshold schema and is used to distribute a secret accessible from entities that have one or more privileges.

Attribute-Based Encryption and Shamir's Secret Sharing work together to guarantee resource confidentiality. An attribute-based key protects each resource. The sharing technique can only recover the correct key to decode the resource if you have the necessary attributes.

## Attribute Based Encryption


## Shamir's Secret Sharing

Given a secret $S$, Shamir's Secret Sharing aims to split the secret into $n$ pieces $S_1, \cdots, S_n$ called shares, in such a way that:
- the secret $S$ is easily computed if you know any $t$ or more parts;
- the secret $S$ can't be reconstructed with fewer than $t$ pieces.

Shamir's Secret Sharing is based on the Lagrange interpolation theorem, which states that $t$ points are sufficient to uniquely calculate a polynomial of degree less than or equal to $t-1$.

Moreover, a finite field $GF(q)$ of order $q$ is used with the intention of providing a higher security level. It must be $q>S, q>n$.

We generate the polynomial $f(x)=\sum_{i=0}^{t-1} a_{i}x^{i} \bmod q$ by choosing $a_0 = S \in GF(q)$ and picking $t-1$ random components $a_1, \cdots, a_{t-1} \in GF(q)$. Let us create any $n$ points $(x_0, y_0), \cdots, (x_{n-1}, y_{n-1})$ out of it. Every participant is given at least one point, whose ordinate needs to be a non-zero in order not to reveal the secret.

Since everyone who receives a share also has to know the value of $q$, it may be considered to be publicly known. Therefore, one should select a value for $q$ that is not too low.

Interpolation can be used to obtain $a_0$ from any subset of $t$ of these pairs. Lagrange interpolation is formulated as follows. Given a set of $t$ points $(x_0, y_0), \cdots, (x_{t-1}, y_{t-1})$, where no two $x_j$ are the same, the interpolation polynomial in the Lagrange form is a linear combination
$$ L(x):=\sum_{j=0}^{t-1}y_jl_j(x) \bmod q$$ of Lagrange basis polynomials
$$ l_j(x):=\prod_{\begin{array}{cc} 0\le m\le t\\ m\ne j \end{array}} \frac{x-x_m} {x_j-x_m} $$
where $0\le j\le t$.

[comment] <> Add how it was done: library, etc