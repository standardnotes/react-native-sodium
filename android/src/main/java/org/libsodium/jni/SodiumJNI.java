package org.libsodium.jni;

public class SodiumJNI {
  public final static native int sodium_init();
  public final static native String sodium_version_string();

  public final static native long randombytes_random();
  public final static native void randombytes_buf(byte[] buf, int size);

  public final static native int crypto_pwhash(byte[] out, final long olen, final byte[] password, final long plen, byte[] salt, long opslimit, long memlimit, int algo);
  public final static native int crypto_pwhash_salt_bytes();
  public final static native int crypto_pwhash_opslimit_moderate();
  public final static native int crypto_pwhash_opslimit_min();
  public final static native int crypto_pwhash_opslimit_max();
  public final static native int crypto_pwhash_memlimit_moderate();
  public final static native int crypto_pwhash_memlimit_min();
  public final static native int crypto_pwhash_memlimit_max();
  public final static native int crypto_pwhash_algo_default();
  public final static native int crypto_pwhash_algo_argon2i13();
  public final static native int crypto_pwhash_algo_argon2id13();

  public final static native int crypto_aead_chacha20poly1305_IETF_ABYTES();
  public final static native int crypto_aead_xchacha20poly1305_IETF_KEYBYTES();
  public final static native int crypto_aead_xchacha20poly1305_IETF_NPUBBYTES();
  public final static native int crypto_aead_xchacha20poly1305_IETF_NSECBYTES();

  public final static native int base64_variant_ORIGINAL();
  public final static native int base64_variant_VARIANT_ORIGINAL_NO_PADDING();
  public final static native int base64_variant_VARIANT_URLSAFE();
  public final static native int base64_variant_VARIANT_URLSAFE_NO_PADDING();

  public final static native char sodium_bin2base64(byte[] b64, final int b64_maxlen, final byte[] bin, final int bin_len, final int variant);
  public final static native int sodium_base642bin(final byte[] bin, int bin_maxlen, final byte[] b64, final int b64_len, final byte[] ignore, int[] bin_len, final byte[] b64_end, final int variant);
  public final static native char sodium_bin2hex(byte[] hex, int hex_maxlen, byte[] bin, final int bin_len);
  public final static native int sodium_hex2bin(byte[] bin, final int bin_maxlen, final byte[] hex, final int hex_len, final byte[] ignore, int[] bin_len, final byte[] hex_end);
  public final static native int sodium_base64_encoded_len(final int bin_len, final int variant);

  public final static native char crypto_aead_xchacha20poly1305_ietf_keygen(byte[] k);
  public final static native int crypto_aead_xchacha20poly1305_ietf_encrypt(byte[] c, int[] clen_p, final byte[] m, final int mlen, final byte[] ad, final int adlen, final byte[] nsec, final byte[] npub, final byte[] k);
  public final static native int crypto_aead_xchacha20poly1305_ietf_decrypt(byte[] m, int[] mlen_p, byte[] nsec, byte[] c, int clen, byte[] ad, int adlen, byte[] npub, byte[] k);
}
