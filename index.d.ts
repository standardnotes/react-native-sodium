export type KeyType = 'curve25519' | 'ed25519' | 'x25519';

export interface CryptoBox {
  ciphertext: string;
  mac: string;
}

export interface StringCryptoBox {
  ciphertext: string;
  mac: string;
}

export interface CryptoKX {
  sharedRx: string;
  sharedTx: string;
}

export interface StringCryptoKX {
  sharedRx: string;
  sharedTx: string;
}

export interface KeyPair {
  keyType: KeyType;
  privateKey: string;
  publicKey: string;
}

export interface StringKeyPair {
  pk: string;
  sk: string;
}

export interface SecretBox {
  cipher: string;
  mac: string;
}

export interface StringSecretBox {
  cipher: string;
  mac: string;
}

export interface StateAddress {
  name: string;
}

export interface MessageTag {
  message: string;
  tag: number;
}

export interface StringMessageTag {
  message: string;
  tag: number;
}

export const crypto_auth_BYTES: number;
export const crypto_auth_KEYBYTES: number;
export const crypto_box_BEFORENMBYTES: number;
export const crypto_box_MACBYTES: number;
export const crypto_box_MESSAGEBYTES_MAX: number;
export const crypto_box_NONCEBYTES: number;
export const crypto_box_PUBLICKEYBYTES: number;
export const crypto_box_SEALBYTES: number;
export const crypto_box_SECRETKEYBYTES: number;
export const crypto_box_SEEDBYTES: number;
export const crypto_generichash_BYTES_MAX: number;
export const crypto_generichash_BYTES_MIN: number;
export const crypto_generichash_BYTES: number;
export const crypto_generichash_KEYBYTES_MAX: number;
export const crypto_generichash_KEYBYTES_MIN: number;
export const crypto_generichash_KEYBYTES: number;
export const crypto_hash_BYTES: number;
export const crypto_kdf_BYTES_MAX: number;
export const crypto_kdf_BYTES_MIN: number;
export const crypto_kdf_CONTEXTBYTES: number;
export const crypto_kdf_KEYBYTES: number;
export const crypto_kx_PUBLICKEYBYTES: number;
export const crypto_kx_SECRETKEYBYTES: number;
export const crypto_kx_SEEDBYTES: number;
export const crypto_kx_SESSIONKEYBYTES: number;
export const crypto_pwhash_ALG_ARGON2I13: number;
export const crypto_pwhash_ALG_ARGON2ID13: number;
export const crypto_pwhash_ALG_DEFAULT: number;
export const crypto_pwhash_BYTES_MAX: number;
export const crypto_pwhash_BYTES_MIN: number;
export const crypto_pwhash_MEMLIMIT_INTERACTIVE: number;
export const crypto_pwhash_MEMLIMIT_MAX: number;
export const crypto_pwhash_MEMLIMIT_MIN: number;
export const crypto_pwhash_MEMLIMIT_MODERATE: number;
export const crypto_pwhash_MEMLIMIT_SENSITIVE: number;
export const crypto_pwhash_OPSLIMIT_INTERACTIVE: number;
export const crypto_pwhash_OPSLIMIT_MAX: number;
export const crypto_pwhash_OPSLIMIT_MIN: number;
export const crypto_pwhash_OPSLIMIT_MODERATE: number;
export const crypto_pwhash_OPSLIMIT_SENSITIVE: number;
export const crypto_pwhash_PASSWD_MAX: number;
export const crypto_pwhash_PASSWD_MIN: number;
export const crypto_pwhash_SALTBYTES: number;
export const crypto_pwhash_STR_VERIFY: number;
export const crypto_pwhash_STRBYTES: number;
export const crypto_pwhash_STRPREFIX: string;
export const crypto_scalarmult_BYTES: number;
export const crypto_scalarmult_SCALARBYTES: number;
export const crypto_secretbox_KEYBYTES: number;
export const crypto_secretbox_MACBYTES: number;
export const crypto_secretbox_MESSAGEBYTES_MAX: number;
export const crypto_secretbox_NONCEBYTES: number;
export const crypto_aead_xchacha20poly1305_IETF_ABYTES: number;
export const crypto_aead_xchacha20poly1305_IETF_KEYBYTES: number;
export const crypto_aead_xchacha20poly1305_IETF_NPUBBYTES: number;
export const crypto_aead_xchacha20poly1305_IETF_NSECBYTES: number;
export const crypto_shorthash_BYTES: number;
export const crypto_shorthash_KEYBYTES: number;
export const crypto_sign_BYTES: number;
export const crypto_sign_MESSAGEBYTES_MAX: number;
export const crypto_sign_PUBLICKEYBYTES: number;
export const crypto_sign_SECRETKEYBYTES: number;
export const crypto_sign_SEEDBYTES: number;
export const randombytes_SEEDBYTES: number;
export const base64_variant_ORIGINAL: number;
export const base64_variant_VARIANT_ORIGINAL_NO_PADDING: number;
export const base64_variant_VARIANT_URLSAFE: number;
export const base64_variant_VARIANT_URLSAFE_NO_PADDING: number;

export const ready: Promise<void>;

export function crypto_auth(message: string, key: string): Promise<string>;

export function crypto_auth_verify(
  tag: string,
  message: string,
  key: string
): Promise<number>;

export function crypto_box_beforenm(
  publicKey: string,
  privateKey: string
): Promise<string>;

export function crypto_box_easy(
  message: string,
  nonce: string,
  publicKey: string,
  privateKey: string
): Promise<string>;

export function crypto_box_easy_afternm(
  message: string,
  nonce: string,
  sharedKey: string
): Promise<string>;

export function crypto_box_keypair(): StringKeyPair;

export function crypto_box_open_easy(
  ciphertext: string,
  nonce: string,
  publicKey: string,
  privateKey: string
): Promise<string>;

export function crypto_box_open_easy_afternm(
  ciphertext: string,
  nonce: string,
  sharedKey: string
): Promise<string>;

export function crypto_box_seal(
  message: string,
  publicKey: string
): Promise<string>;

export function crypto_box_seal_open(
  ciphertext: string,
  publicKey: string,
  privateKey: string
): Promise<string>;

export function crypto_pwhash(
  keyLength: number,
  password: string,
  salt: string,
  opsLimit: number,
  memLimit: number,
  algorithm: number
): Promise<string>;

export function crypto_scalarmult(
  privateKey: string,
  publicKey: string
): Promise<string>;

export function crypto_scalarmult_base(privateKey: string): Promise<string>;

export function crypto_secretbox_easy(
  message: string,
  nonce: string,
  key: string
): Promise<string>;

export function crypto_secretbox_open_easy(
  ciphertext: string,
  nonce: string,
  key: string
): Promise<string>;

export function crypto_sign(
  message: string,
  privateKey: string
): Promise<string>;

export function crypto_sign_detached(
  message: string,
  privateKey: string
): Promise<string>;

export function crypto_sign_ed25519_pk_to_curve25519(
  edPk: string
): Promise<string>;

export function crypto_sign_ed25519_sk_to_curve25519(
  edSk: string
): Promise<string>;

export function crypto_aead_xchacha20poly1305_ietf_encrypt(
  message: string,
  public_nonce: string,
  key: string,
  additional_data: string | null
): Promise<string>;

export function crypto_aead_xchacha20poly1305_ietf_decrypt(
  cipherText: string,
  public_nonce: string,
  key: string,
  additional_data: string | null
): Promise<string>;

export function crypto_aead_xchacha20poly1305_ietf_keygen(): Promise<string>;

export function crypto_sign_keypair(): StringKeyPair;

export function crypto_sign_seed_keypair(seed: string): StringKeyPair;

export function crypto_sign_verify_detached(
  signature: string,
  message: string,
  publicKey: string
): Promise<boolean>;

export function randombytes_buf(length: number): Promise<string>;

export function randombytes_close(): void;

export function randombytes_random(): Promise<number>;

export function randombytes_stir(): void;

export function randombytes_uniform(upper_bound: number): Promise<number>;

export function sodium_version_string(): Promise<string>;

export function to_base64(message: string, variant: number): Promise<string>;

export function from_base64(cipher: string, variant: number): Promise<string>;

export function to_hex(message: string): Promise<string>;

export function from_hex(cipher: string): Promise<string>;
