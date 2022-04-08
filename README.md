
# READ ME for LumoSQL ABE-SSS

## Introduction
LumoSQL is an ambitious project that aims to bring encrypted storage modes to SQLite embedded databases, while keeping the standard SQL-GRANT syntax. In this context, encryption is one of the major problems. LumoSQL not only strives for data confidentiality, but also for more fine-grained data protection. It aspires to be able to encrypt the whole database as well as single tables or columns. The above said contributes to support the ambitious nature of this objective and the complexity of the issues involved. In fact, current solutions only offer a full encryption database with a unique key.

Attribute-Based Encryption-Shamir's Secret Sharing (ABE-SSS) is part of LumoSQL project.

Attribute-Based Encryption is an asymmetric cryptographic primitive in which the ciphertext and the user's secret key are both determined by attributes. Only if the set of attributes of the user key matches the attributes of the ciphertext can a ciphertext be decrypted in such a system. Since LumoSQL intends retaining GRANT-style syntax, Attribute-Based Encryption perfectly maps GRANT-style privileges.

Shamir's Secret Sharing is one of the first cryptographic secret sharing techniques. It allows to split a secret number $s$ into $n$ shares and, given a threshold $k < n$ of shares, we can reconstruct $s$. Shamir's Secret Sharing can be also classified as a $(k, n)$-threshold schema and is used to distribute a secret accessible from entities that have one or more privileges.

## Shamir's Secret Sharing






## Attribute Based Encryption


## ABE-SSS

