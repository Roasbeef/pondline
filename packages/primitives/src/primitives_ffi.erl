%% The one Erlang shim of the primitives package: thin wrappers over OTP's
%% crypto module, which is linked against OpenSSL.
%%
%% Every fallible key or verification wrapper catches every exception and
%% returns {error, nil} or false. That is a security property, not tidiness:
%% OTP's crypto raises errors whose arguments include the key material it was
%% handed, so an uncaught error there would print a private key into a crash
%% report. Unkeyed helpers and total digests (sha256/1, hmac_sha256/2, equal/2,
%% random_bytes/1, keypair generation, openssl_version/0) stay plain calls; see
%% sha256/1 below.
-module(primitives_ffi).

-export([random_bytes/1,
         sha256/1, hmac_sha256/2, equal/2,
         x25519_keypair/0, x25519_public/1, x25519/2,
         ed25519_keypair/0, ed25519_public/1, ed25519_sign/2, ed25519_verify/3,
         mlkem1024_keypair/0, mlkem1024_encapsulate/1, mlkem1024_decapsulate/2,
         mldsa65_keypair/0, mldsa65_sign/2, mldsa65_verify/3,
         aead_seal/4, aead_open/4,
         openssl_version/0]).

-define(GUARD(Expr), try {ok, Expr} catch _:_ -> {error, nil} end).

random_bytes(N) when is_integer(N), N >= 0 -> crypto:strong_rand_bytes(N).

%% sha256/1 and hmac_sha256/2 are not wrapped in ?GUARD, so that the Gleam
%% API stays a plain BitArray. They cannot raise for the byte-aligned
%% binaries every caller in this repository passes: crypto:hash/2 and
%% crypto:mac/4 raise only on a non-binary or non-byte-aligned bitstring,
%% and an HMAC key of any length is valid. Neither carries a secret in a
%% raised error the way the key operations below could.
sha256(Data) -> crypto:hash(sha256, Data).

hmac_sha256(Key, Data) -> crypto:mac(hmac, sha256, Key, Data).

%% Constant-time comparison. hash_equals requires equal lengths, and a
%% length difference is not secret here, so it short-circuits to false.
equal(A, B) when byte_size(A) =:= byte_size(B) -> crypto:hash_equals(A, B);
equal(_, _) -> false.

x25519_keypair() ->
    {Public, Secret} = crypto:generate_key(ecdh, x25519),
    {Secret, Public}.

x25519_public(Secret) when byte_size(Secret) =:= 32 ->
    ?GUARD(element(1, crypto:generate_key(ecdh, x25519, Secret)));
x25519_public(_) -> {error, nil}.

%% OpenSSL refuses a shared secret of all zeros (a low-order public key),
%% which is the RFC 7748 section 6.1 check; the guard turns that refusal
%% into an error rather than a crash.
x25519(Secret, Public) when byte_size(Secret) =:= 32, byte_size(Public) =:= 32 ->
    ?GUARD(crypto:compute_key(ecdh, Public, Secret, x25519));
x25519(_, _) -> {error, nil}.

ed25519_keypair() ->
    {Public, Secret} = crypto:generate_key(eddsa, ed25519),
    {Secret, Public}.

ed25519_public(Secret) when byte_size(Secret) =:= 32 ->
    ?GUARD(element(1, crypto:generate_key(eddsa, ed25519, Secret)));
ed25519_public(_) -> {error, nil}.

ed25519_sign(Secret, Message) when byte_size(Secret) =:= 32 ->
    ?GUARD(crypto:sign(eddsa, none, Message, [Secret, ed25519]));
ed25519_sign(_, _) -> {error, nil}.

ed25519_verify(Public, Message, Signature)
  when byte_size(Public) =:= 32, byte_size(Signature) =:= 64 ->
    try crypto:verify(eddsa, none, Message, Signature, [Public, ed25519])
    catch _:_ -> false
    end;
ed25519_verify(_, _, _) -> false.

mlkem1024_keypair() ->
    {Public, Secret} = crypto:generate_key(mlkem1024, []),
    {Secret, Public}.

%% Returns {SharedSecret, Ciphertext}.
mlkem1024_encapsulate(Public) when byte_size(Public) =:= 1568 ->
    ?GUARD(crypto:encapsulate_key(mlkem1024, Public));
mlkem1024_encapsulate(_) -> {error, nil}.

%% ML-KEM decapsulation uses implicit rejection: a well-sized but forged
%% ciphertext yields an unrelated secret rather than an error, so the
%% only error here is a malformed size or key.
mlkem1024_decapsulate(Secret, Ciphertext)
  when byte_size(Secret) =:= 3168, byte_size(Ciphertext) =:= 1568 ->
    ?GUARD(crypto:decapsulate_key(mlkem1024, Secret, Ciphertext));
mlkem1024_decapsulate(_, _) -> {error, nil}.

%% ML-DSA-65 (FIPS 204). The secret is OpenSSL's expanded private key, 4032
%% bytes; OTP 29 cannot rebuild a key pair from the 32-byte seed through
%% generate_key/3, so the expanded form is what Pondline stores. Signing is
%% OpenSSL's default hedged mode, which mixes fresh randomness into every
%% signature, so two signatures of one message differ and both verify.
mldsa65_keypair() ->
    {Public, Secret} = crypto:generate_key(mldsa65, []),
    {Secret, Public}.

mldsa65_sign(Secret, Message) when byte_size(Secret) =:= 4032 ->
    ?GUARD(crypto:sign(mldsa65, none, Message, Secret));
mldsa65_sign(_, _) -> {error, nil}.

%% A wrong-sized public key makes crypto:verify raise rather than return
%% false, and the raised error carries the key; the size guard and the catch
%% both turn that into false.
mldsa65_verify(Public, Message, Signature)
  when byte_size(Public) =:= 1952, byte_size(Signature) =:= 3309 ->
    try crypto:verify(mldsa65, none, Message, Signature, Public) of
        true -> true;
        _ -> false
    catch _:_ -> false
    end;
mldsa65_verify(_, _, _) -> false.

%% ChaCha20-Poly1305 (RFC 8439). The output is the ciphertext with the
%% 16-byte tag appended.
aead_seal(Key, Nonce, Aad, Plaintext) when byte_size(Key) =:= 32, byte_size(Nonce) =:= 12 ->
    case ?GUARD(crypto:crypto_one_time_aead(chacha20_poly1305, Key, Nonce, Plaintext, Aad, true)) of
        {ok, {Ciphertext, Tag}} -> {ok, <<Ciphertext/binary, Tag/binary>>};
        _ -> {error, nil}
    end;
aead_seal(_, _, _, _) -> {error, nil}.

aead_open(Key, Nonce, Aad, Sealed)
  when byte_size(Key) =:= 32, byte_size(Nonce) =:= 12, byte_size(Sealed) >= 16 ->
    Size = byte_size(Sealed) - 16,
    <<Ciphertext:Size/binary, Tag:16/binary>> = Sealed,
    case ?GUARD(crypto:crypto_one_time_aead(chacha20_poly1305, Key, Nonce, Ciphertext, Aad, Tag, false)) of
        {ok, Plaintext} when is_binary(Plaintext) -> {ok, Plaintext};
        _ -> {error, nil}
    end;
aead_open(_, _, _, _) -> {error, nil}.

openssl_version() ->
    [{_, _, Version} | _] = crypto:info_lib(),
    Version.
