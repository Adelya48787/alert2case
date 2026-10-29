# Cryptography
The names of files are same with the names of README subtitles. You can match each of them easily
# GCD
This project implements a function to calculate the Greatest Common Divisor (GCD) of two integers using → Recursion, Euclidean Algortihm, and Modulo operator(%).
As you see, gcd(a,b) = gcd(b,a % b) this process will continue until the second number becomes zero.
In that case, we are able to get the gcd of two numbers.


# Caesar and affine ciphers
This project implements two basic encryption algorithms:
- **Caesar Cipher**
- **Affine Cipher**

---

## 📌 How It Works

### 1. Caesar Cipher
- Each letter is shifted by a fixed number (**key k**)
- Example: hello → mjqqt (k = 5) (mentioned in a code as comment, you may use while running)
- Features:
- Preserves uppercase and lowercase
- Keeps spaces and symbols unchanged

---

### 2. Affine Cipher
- Uses the formula: E(x) = (a * x + b) mod 26
- Decryption: D(x) = a⁻¹(x - b) mod 26
- Important:
- `a` must be **coprime with 26** (e.g., 5, 7, 11, 17…)
- Otherwise, decryption will fail

FILENAME → Ceaser and Affine ciphers.py

# OTP
This project implements the OTP encryption algorithm.
In my code the length of key equals to the message length.
Let's dive into the code:
________________________________________________________
Firstly, ENCRYPTION part..
1. The PlainText is provided by the user
2. Each character is converted into its ASCII integer value → `ascii (s)` converts string to integer in termd of ASCII and returns list of integers(ASCII)
3. Each ASCII value is converted into 8-bit binary format. → `binary_converter(ls)` in this part, we need to pay attention to adding zeros until completing 8 digits.
4.  A random key is generated with length → key length = length of plaintext × 8 bits.
   `key_generator(s)`

6.  Plaintext binary block is XORed with the generated key. `XOR(bin,key)` this part will work for both encryption and decryption
7.  One more part related to → `decimal_converter(c_bin)` → `cipher (decimal)` base64
___________________________________________________
Secondly, DECRYPTION part..
1. CipherText is provided by the user.
2. Decrypting the part which was mentioned above in the step 7. →`(binary_converter(plain(c)),key)`
   Each character is converted into ASCII decimal, and each decimal is converted into 8-bit binary
4.  CipherText binary block is XORed with the generated key. `XOR(bin,key)` this part will work for both encryption and decryption
5.  The result is converted back into ASCII decimal → `decimal_converter(bin)`
6.  Finally, ASCII values are converted back into ASCII decimal → `ascii_elements(decimal)`



# OTP + PRG
In OTP + PRG, instead of using a fully random key, we generate the key using a Pseudo Random Generator (PRG).
A PRG takes a short random seed as input and expands it into a long pseudorandom key stream. (`generate_prg_key(seed, length)`)
This key stream is then used in the OTP XOR process to encrypt the message.


# Frequency Analysis Attack
This project implements a **Caesar Cipher decryption tool** enhanced with **frequency analysis** to automatically guess the most likely shift.

It works by:

* Counting letter frequencies in the ciphertext
* Comparing them with typical English letter frequency
* Estimating the shift used in the Caesar cipher


## How It Works

### 1. `caesar_dec(text, shift)`

* Shifts each letter by a given value
* Handles both lowercase and uppercase letters
* Leaves non-alphabet characters unchanged

### 2. `frequency_order(c)`

* Counts occurrences of each letter in ciphertext
* Sorts characters by frequency (most frequent first)

### 3. Frequency Matching

The code uses a known English frequency order:

```
freq_order = "etaoinshrdlcumwfgypbvkjxqz"
```

Then:

* Takes the most frequent letter in ciphertext
* Assumes it corresponds to `'e'` (most common in English)
* Computes the shift

---


### Input:

```
Ciphertext → Xultpaajcxitltlxaarpjhtiwtgxktghidhipxciwtvgtpilpitghlxiwiwtxgqadds
```

### Output:

```
Possible decryption:
x → e | Shift  11: Ifweallunitewewillcausetheriverstostainthegreatwaterswiththeirblood.
```



# CPA-secure OTP (The file named as CPA)
This project implements a **stream cipher using AES** as a pseudorandom function with a **nonce + counter construction** (similar to CTR mode).

The program:

* Generates a secure keystream using AES
* Encrypts plaintext using XOR
* Decrypts ciphertext using the same keystream

---


The encryption follows the stream cipher model:

```
Ciphertext = Plaintext ⊕ Keystream
Plaintext  = Ciphertext ⊕ Keystream
```

The keystream is generated using:

* AES (ECB mode internally)
* A random key
* A nonce + counter
---
### 1. XOR Operation

```python
XOR(x, y)
```

* Performs byte-wise XOR between two byte strings
* Used for both encryption and decryption

---

### 2. Counter Block Generation

```python
convert_bytes(cnt)
```

* Converts an integer counter into an 8-byte representation
* Ensures fixed-size counter blocks

---

### 3. Keystream Generator

```python
make_stream(key, nonce, length)
```

* Uses AES in ECB mode
* For each block:

  * Combines nonce (8 bytes) + counter (8 bytes)
  * Encrypts the block
* Concatenates outputs to produce a keystream

---

### 4. Encryption

```python
encrypt(key, message)
```

* Converts message to bytes (if needed)
* Generates a random 8-byte nonce
* Produces keystream
* XORs message with keystream
* Returns: `nonce + ciphertext`

---

### 5. Decryption

```python
decrypt(key, data)
```

* Extracts nonce from first 8 bytes
* Regenerates the same keystream
* XORs ciphertext to recover plaintext

---

### Input:

```
Message: HELLO
```

### Output:

```
The Encrypted: <hex ciphertext>
The Decrypted: HELLO
```












# Extended Euclidian algorithm
This project demonstrates how to compute the **modular inverse** of a number using the **Extended Euclidean Algorithm**
The modular inverse of `a` modulo `m` is a number `x` such that:
```
a * x ≡ 1 (mod m)
```
This inverse exists **only when** `gcd(a, m) = 1`.

## How It Works
The code consists of two main functions:
### 1. `extended_gcd(a, m)`
* Performs the Euclidean Algorithm
* Prints each division step
* Stores equations for traceability
* Checks whether the modular inverse exists
### 2. `extended_euclidean(a, b)`
* Recursively computes:
  * `gcd(a, b)`
  * Coefficients `x` and `y` such that:
```
a * x + b * y = gcd(a, b)
```

* If `gcd(a, b) = 1`, then `x` is the modular inverse of `a mod b`

---

##  Example

```python
a = 12
b = 67
```

### Output:

```
67 = 5*12 + 7
12 = 1*7 + 5
7 = 1*5 + 2
5 = 2*2 + 1
2 = 2*1 + 0
12 * (-28) + 67 * (5) = 1
Hence, -28 is the inverse of 12 mod 67
```

## Notes

* If `gcd(a, b) ≠ 1`, modular inverse does **not** exist
* The result `x` may be negative — you can convert it to a positive equivalent:
* I you want you can add a and b by yourself: (just use `int(input('a: '))`, `int(input('b: '))` )

```python
x = x % b
```



# RSA Encryption scheme
Firstly, message is required from you (`Message: `). For example: Message: 11
Secondly, Public key and Private key comes into the display, as `(N,e)` and `(N, d)`, respectively.
Then, you will see `Encrypted: ` and `Decrypted: ` parts

### Notes:
While running you may change the start and end points for key generation (I have also noted in the code, next to generate_prime())
You may also observe the result for p,q, and phi, which I have commented `print()` inside `generate_keys()`
RSA only works correctly when `0 <= m < N`, otherwise ERROR will come into play
### Key Generation
1. Generate two distinct prime numbers `p` and `q` → `generate_keys()`
2. Compute
   - `N = p * q`
   - `phi = (p - 1) * (q - 1)`
3. Choose `e` such that
   - `gcd(e, phi) = 1`
4. Compute
   - `d = e^(-1) mod phi` (e inverse)

- Public key: `(N, e)`
- Private key: `(N, d)`


### Encryption and Decryption
- encrypt(m, public_key) → m is message
- decrypt(c, private_key) → c is cipher
- `gcd(e, phi(N)) = 1` is required for the modular inverse
- This implementation is **not secure** (small primes, no padding)
- Real RSA requires large primes and secure padding

# Diffie-Hellman key exchange
Two parties (Alice and Bob) generate a shared secret key using public and private values.

In this implementation, the public parameters ( q ) (a prime modulus) and ( g ) (a generator) are predefined within the code. However, you may alternatively provide these values manually by uncommenting the input lines (`int(input('q: '))` or `int(input('g: '))`), which are already included in the code.
The key exchange process is executed by calling the `diffie_hellman(q,g)` function. Within this function, Alice and Bob independently generate their private keys and compute their corresponding public keys. These public keys are then exchanged between the two parties.

- Alice computes (g^(yx) mod q)
- Bob computes (g^(xy) mod q)

The function returns a dictionary, I have demonstrated the dictionary's content on the screen, in a structured way

On top of that, the code includes a verification step to ensure the correctness of the exchange. The shared secrets computed by Alice and Bob are compared. If they are equal, a success message is displayed. This check is important, as discrepancies may occur due to data alteration, transmission errors, or potential security issues. If the shared secrets do not match, the program indicates that `Error: shared secrets do not match.`



# PRG based on discrete-log
This program implements a simple pseudorandom generator based on modular exponentiation and the discrete logarithm idea, generating bits from values like `g ^ x mod q`, `g ^ y mod q`, `g ^ (xy) mod q` modulo a prime. It expands random seeds into longer bitstrings by iteratively applying exponentiation and extracting bits.
In the code, I have already added the values for the defined variables.
- Generate `g ^ x mod q`, `g ^ y mod q`, `g ^ (xy) mod q`
- q: prime modulus
- g: generator
- x,y: random seeds
- num_bits: bits per stream
