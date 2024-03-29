# Copyright (C) 2017-2023, ISARA Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required (VERSION 3.7)
cmake_policy (SET CMP0054 NEW)

project(samples)

set (
    samples

    # Common sample code. Builds a small static library.
    common

    # Individual samples.
    aead_chacha20_poly1305/decrypt
    aead_chacha20_poly1305/encrypt
    chacha20/decrypt
    chacha20/encrypt
    classicmceliece/decapsulate
    classicmceliece/encapsulate
    classicmceliece/generate_keys
    dilithium/generate_keys
    dilithium/sign
    dilithium/verify
    hash
    hss/detach
    hss/generate_keys
    hss/sign
    hss/verify
    hss/verify_from_sig
    kdf/concatenation
    kdf/pbkdf2
    kdf/rfc5869
    kyber/decapsulate
    kyber/encapsulate
    kyber/generate_keys
    mac/hmac
    mac/poly1305
    rng
    sphincs/generate_keys
    sphincs/sign
    sphincs/verify
    version
    xmss/detach
    xmss/generate_keys
    xmss/sign
    xmss/verify
    xmss/verify_from_public

    # Integration samples. These are only built if your system has the
    # necessary dependencies.
    integration/hash-openssl    # Requires OpenSSL development headers/libraries.
    integration/rng-cng         # Requires Windows CNG.
    integration/rng-urandom     # Requires a /dev/random device.
)

foreach(sample ${samples})
    add_subdirectory(${sample})
endforeach(sample ${SAMPLES})
