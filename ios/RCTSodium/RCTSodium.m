//
//  RCTSodium.m
//  RCTSodium
//
//  Created by Lyubomir Ivanov on 9/25/16.
//  Copyright © 2016 Lyubomir Ivanov. All rights reserved.
//
#import "RCTBridgeModule.h"
#import "RCTUtils.h"
#import "sodium.h"

#import "RCTSodium.h"

@implementation RCTSodium

static bool isInitialized;

NSString * const ESODIUM = @"ESODIUM";
NSString * const ERR_BAD_KEY = @"BAD_KEY";
NSString * const ERR_BAD_MAC = @"BAD_MAC";
NSString * const ERR_BAD_MSG = @"BAD_MSG";
NSString * const ERR_BAD_NONCE = @"BAD_NONCE";
NSString * const ERR_BAD_SEED = @"BAD_SEED";
NSString * const ERR_BAD_SIG = @"BAD_SIG";
NSString * const ERR_FAILURE = @"FAILURE";

RCT_EXPORT_MODULE();

+ (void) initialize
{
    [super initialize];
    isInitialized = sodium_init() != -1;
}


// *****************************************************************************
// * Sodium constants
// *****************************************************************************
- (NSDictionary *)constantsToExport
{
    return @{
        @"crypto_secretbox_KEYBYTES": @ crypto_secretbox_KEYBYTES,
        @"crypto_secretbox_NONCEBYTES": @ crypto_secretbox_NONCEBYTES,
        @"crypto_secretbox_MACBYTES": @ crypto_secretbox_MACBYTES,
        @"crypto_auth_KEYBYTES": @crypto_auth_KEYBYTES,
        @"crypto_auth_BYTES": @crypto_auth_BYTES,
        @"crypto_box_PUBLICKEYBYTES": @crypto_box_PUBLICKEYBYTES,
        @"crypto_box_SECRETKEYBYTES": @crypto_box_SECRETKEYBYTES,
        @"crypto_box_NONCEBYTES": @crypto_box_NONCEBYTES,
        @"crypto_box_MACBYTES": @crypto_box_MACBYTES,
        @"crypto_box_SEALBYTES": @crypto_box_SEALBYTES,
        @"crypto_sign_PUBLICKEYBYTES": @crypto_sign_PUBLICKEYBYTES,
        @"crypto_sign_SECRETKEYBYTES": @crypto_sign_SECRETKEYBYTES,
        @"crypto_sign_SEEDBYTES": @crypto_sign_SEEDBYTES,
        @"crypto_sign_BYTES": @crypto_sign_BYTES,
        @"crypto_pwhash_SALTBYTES": @crypto_pwhash_SALTBYTES,
        @"crypto_pwhash_OPSLIMIT_MODERATE":@crypto_pwhash_OPSLIMIT_MODERATE,
        @"crypto_pwhash_OPSLIMIT_MIN":@crypto_pwhash_OPSLIMIT_MIN,
        @"crypto_pwhash_OPSLIMIT_MAX":@crypto_pwhash_OPSLIMIT_MAX,
        @"crypto_pwhash_MEMLIMIT_MODERATE":@crypto_pwhash_MEMLIMIT_MODERATE,
        @"crypto_pwhash_MEMLIMIT_MIN":@crypto_pwhash_MEMLIMIT_MIN,
        @"crypto_pwhash_MEMLIMIT_MAX":@crypto_pwhash_MEMLIMIT_MAX,
        @"crypto_pwhash_ALG_DEFAULT":@crypto_pwhash_ALG_DEFAULT,
        @"crypto_pwhash_ALG_ARGON2I13":@crypto_pwhash_ALG_ARGON2I13,
        @"crypto_pwhash_ALG_ARGON2ID13":@crypto_pwhash_ALG_ARGON2ID13,
        @"crypto_aead_xchacha20poly1305_IETF_ABYTES":@crypto_aead_chacha20poly1305_IETF_ABYTES,
        @"crypto_aead_xchacha20poly1305_IETF_KEYBYTES":@crypto_aead_xchacha20poly1305_IETF_KEYBYTES,
        @"crypto_aead_xchacha20poly1305_IETF_NPUBBYTES":@crypto_aead_xchacha20poly1305_IETF_NPUBBYTES,
        @"crypto_aead_xchacha20poly1305_IETF_NSECBYTES":@crypto_aead_xchacha20poly1305_IETF_NSECBYTES,
        @"base64_variant_ORIGINAL":@sodium_base64_VARIANT_ORIGINAL,
        @"base64_variant_VARIANT_ORIGINAL_NO_PADDING":@sodium_base64_VARIANT_ORIGINAL_NO_PADDING,
        @"base64_variant_VARIANT_URLSAFE":@sodium_base64_VARIANT_URLSAFE,
        @"base64_variant_VARIANT_URLSAFE_NO_PADDING":@sodium_base64_VARIANT_URLSAFE_NO_PADDING,
    };

}

+ (BOOL)requiresMainQueueSetup
{
    return NO;
}

// *****************************************************************************
// * Sodium-specific functions
// *****************************************************************************
RCT_EXPORT_METHOD(sodium_version_string:(RCTPromiseResolveBlock)resolve reject:(__unused RCTPromiseRejectBlock)reject)
{
    resolve(@(sodium_version_string()));
}


// *****************************************************************************
// * Random data generation
// *****************************************************************************
RCT_EXPORT_METHOD(randombytes_random:(RCTPromiseResolveBlock)resolve reject:(__unused RCTPromiseRejectBlock)reject)
{
    resolve(@(randombytes_random()));
}

RCT_EXPORT_METHOD(randombytes_uniform:(NSUInteger)upper_bound resolve:(RCTPromiseResolveBlock)resolve reject:(__unused RCTPromiseRejectBlock)reject)
{
    resolve(@(randombytes_uniform((uint32_t)upper_bound)));
}

RCT_EXPORT_METHOD(randombytes_buf:(NSUInteger)size resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    unsigned char *buf = (unsigned char *) sodium_malloc((u_int32_t)size);
    if (buf == NULL)
        reject(ESODIUM,ERR_FAILURE,nil);
    else {
        randombytes_buf(buf,(u_int32_t)size);
        NSData *data = [NSData dataWithBytesNoCopy:buf length:size freeWhenDone:NO];
        const NSString *res = [self binToHex:data];
        resolve(res);
        sodium_free(buf);
    }
}

RCT_EXPORT_METHOD(randombytes_close:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    int result = randombytes_close();
    if (result == 0) resolve(0); else reject(ESODIUM,ERR_FAILURE,nil);
}

RCT_EXPORT_METHOD(randombytes_stir:(RCTPromiseResolveBlock)resolve reject:(__unused RCTPromiseRejectBlock)reject)
{
    randombytes_stir();
    resolve(0);
}


// *****************************************************************************
// * Secret-key cryptography - authenticated encryption
// *****************************************************************************
RCT_EXPORT_METHOD(crypto_secretbox_easy:(NSString*)m n:(NSString*)n k:(NSString*)k resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dm = [[NSData alloc] initWithBase64EncodedString:m options:0];
    const NSData *dn = [[NSData alloc] initWithBase64EncodedString:n options:0];
    const NSData *dk = [[NSData alloc] initWithBase64EncodedString:k options:0];
    if (!dm || !dn || !dk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dk.length != crypto_secretbox_KEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (dn.length != crypto_secretbox_NONCEBYTES) reject(ESODIUM,ERR_BAD_NONCE,nil);
    else {
        unsigned long clen = crypto_secretbox_MACBYTES + dm.length;
        unsigned char *dc = (unsigned char *) sodium_malloc(clen);
        if (dc == NULL) reject(ESODIUM,ERR_FAILURE,nil);
        else {
            int result = crypto_secretbox_easy(dc,[dm bytes], dm.length, [dn bytes], [dk bytes]);
            if (result != 0)
                reject(ESODIUM,ERR_FAILURE,nil);
            else
                resolve([[NSData dataWithBytesNoCopy:dc length:clen freeWhenDone:NO]  base64EncodedStringWithOptions:0]);
            sodium_free(dc);
        }
    }
}


RCT_EXPORT_METHOD(crypto_secretbox_open_easy:(NSString*)c n:(NSString*)n k:(NSString*)k resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dc = [[NSData alloc] initWithBase64EncodedString:c options:0];
    const NSData *dn = [[NSData alloc] initWithBase64EncodedString:n options:0];
    const NSData *dk = [[NSData alloc] initWithBase64EncodedString:k options:0];
    if (!dc || !dn || !dk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dk.length != crypto_secretbox_KEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (dn.length != crypto_secretbox_NONCEBYTES) reject(ESODIUM,ERR_BAD_NONCE,nil);
    else if (crypto_secretbox_open_easy([dc bytes], [dc bytes], dc.length, [dn bytes], [dk bytes]) != 0)
        reject(ESODIUM,ERR_FAILURE,nil);
    else
        resolve([[NSData dataWithBytesNoCopy:[dc bytes] length:dc.length - crypto_secretbox_MACBYTES freeWhenDone:NO]  base64EncodedStringWithOptions:0]);
}

// ***************************************************************************
// * Secret-key cryptography - authentication
// ***************************************************************************
RCT_EXPORT_METHOD(crypto_auth:(NSString*)in k:(NSString*)k resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    unsigned char out[crypto_auth_BYTES];

    const NSData *din = [[NSData alloc] initWithBase64EncodedString:in options:0];
    const NSData *dk = [[NSData alloc] initWithBase64EncodedString:k options:0];
    if (!din || !dk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dk.length != crypto_auth_KEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else {
        crypto_auth(out, [din bytes], (unsigned long long) din.length, [dk bytes]);
        resolve([[NSData dataWithBytesNoCopy:out length:sizeof(out) freeWhenDone:NO]  base64EncodedStringWithOptions:0]);
    }
}

RCT_EXPORT_METHOD(crypto_auth_verify:(NSString*)h in:(NSString*)in k:(NSString*)k resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dh = [[NSData alloc] initWithBase64EncodedString:h options:0];
    const NSData *din = [[NSData alloc] initWithBase64EncodedString:in options:0];
    const NSData *dk = [[NSData alloc] initWithBase64EncodedString:k options:0];
    if (!dh || !din || !dk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dk.length != crypto_auth_KEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (dh.length != crypto_auth_BYTES) reject(ESODIUM,ERR_BAD_MAC,nil);
    else {
        int result = crypto_auth_verify([dh bytes], [din bytes], (unsigned long long) din.length, [dk bytes]);
        resolve(@(result));
    }
}

// *****************************************************************************
// * Public-key cryptography - XChaCha20-Poly1305 encryption
// *****************************************************************************
RCT_EXPORT_METHOD(crypto_aead_xchacha20poly1305_ietf_encrypt:(NSString*)message public_nonce:(NSString*)public_nonce key:(NSString*)key additionalData:(NSString*)additionalData resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *m = [message dataUsingEncoding:NSUTF8StringEncoding];
    const NSData *npub = [self hexToBin:public_nonce];
    const NSData *k = [self hexToBin:key];

    if (!m || !npub || !k) reject(ESODIUM,ERR_FAILURE,nil);
    else if (npub.length != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) reject(ESODIUM,ERR_BAD_NONCE,nil);
    else if (k.length != crypto_aead_xchacha20poly1305_IETF_KEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);

    else {
        unsigned long long clen = crypto_aead_chacha20poly1305_IETF_ABYTES + m.length;
        unsigned char *c = (unsigned char *) sodium_malloc(clen);

        const NSData *ad = additionalData ? [additionalData dataUsingEncoding:NSUTF8StringEncoding] : NULL;
        unsigned long adlen = additionalData ? ad.length : 0;
        if (c == NULL) reject(ESODIUM,ERR_FAILURE,nil);
        else {
            int result = crypto_aead_xchacha20poly1305_ietf_encrypt(c, &clen, [m bytes], m.length, ad ? [ad bytes] : NULL, adlen, NULL, [npub bytes], [k bytes]);
            if (result != 0)
                reject(ESODIUM,ERR_FAILURE,nil);
            else {
                NSData *resultData = [NSData dataWithBytesNoCopy:c length:clen freeWhenDone:NO];
                resolve([self binToBase64:resultData variant:[NSNumber numberWithInt:sodium_base64_VARIANT_ORIGINAL]]);
            }
            sodium_free(c);        }
    }
}

RCT_EXPORT_METHOD(crypto_aead_xchacha20poly1305_ietf_decrypt:(NSString*)cipherText public_nonce:(NSString*)public_nonce key:(NSString*)key additionalData:(NSString*)additionalData resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dc = [self base64ToBin:cipherText variant:[NSNumber numberWithInt:sodium_base64_VARIANT_ORIGINAL]];
    const NSData *dn = [self hexToBin:public_nonce];
    const NSData *dk = [self hexToBin:key];
    if (!dc || !dn || !dk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dk.length != crypto_aead_xchacha20poly1305_IETF_KEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (dn.length != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) reject(ESODIUM,ERR_BAD_NONCE,nil);
    else {
        const NSData *ad = additionalData != NULL ? [additionalData dataUsingEncoding:NSUTF8StringEncoding] : NULL;
        unsigned long adlen = additionalData != NULL ? ad.length : 0;

        unsigned long long decrypted_len = [NSNumber numberWithLongLong: dc.length].unsignedLongLongValue;
        unsigned char* decrypted = (unsigned char *) sodium_malloc(decrypted_len - crypto_aead_chacha20poly1305_IETF_ABYTES);

        if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, NULL, [dc bytes], dc.length, ad ? [ad bytes] : NULL, adlen, [dn bytes], [dk bytes]) == -1) {
            reject(ESODIUM,ERR_FAILURE,nil);
        }
        else {
            NSData *resData = [NSData dataWithBytesNoCopy:decrypted length:decrypted_len freeWhenDone:NO];
            const NSString *res = [[NSString alloc] initWithData:resData encoding:NSUTF8StringEncoding];
            resolve(res);
        }
        sodium_free(decrypted);
    }
}

RCT_EXPORT_METHOD(crypto_aead_xchacha20poly1305_ietf_keygen:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    unsigned char k[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    crypto_aead_xchacha20poly1305_ietf_keygen(k);
    resolve([[NSData dataWithBytesNoCopy:k length:crypto_aead_xchacha20poly1305_ietf_KEYBYTES freeWhenDone:NO]  base64EncodedStringWithOptions:0]);
}

// *****************************************************************************
// * Public-key cryptography - authenticated encryption
// *****************************************************************************
RCT_EXPORT_METHOD(crypto_box_keypair:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    unsigned char pk[crypto_box_PUBLICKEYBYTES],sk[crypto_box_SECRETKEYBYTES];
    if ( crypto_box_keypair(pk,sk) == 0) {
        NSString *pk64 = [[NSData dataWithBytesNoCopy:pk length:sizeof(pk) freeWhenDone:NO]  base64EncodedStringWithOptions:0];
        NSString *sk64 = [[NSData dataWithBytesNoCopy:sk length:sizeof(sk) freeWhenDone:NO]  base64EncodedStringWithOptions:0];
        if (!pk64 || !sk64) reject(ESODIUM,ERR_FAILURE,nil); else resolve(@{@"pk":pk64, @"sk":sk64});
    }
    else
        reject(ESODIUM,ERR_FAILURE,nil);
}

RCT_EXPORT_METHOD(crypto_box_easy:(NSString*)m n:(NSString*)n pk:(NSString*)pk sk:(NSString*)sk resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dm = [[NSData alloc] initWithBase64EncodedString:m options:0];
    const NSData *dn = [[NSData alloc] initWithBase64EncodedString:n options:0];
    const NSData *dpk = [[NSData alloc] initWithBase64EncodedString:pk options:0];
    const NSData *dsk = [[NSData alloc] initWithBase64EncodedString:sk options:0];
    if (!dm || !dn || !dpk || !dsk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dpk.length != crypto_box_PUBLICKEYBYTES || dsk.length != crypto_box_SECRETKEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (dn.length != crypto_box_NONCEBYTES) reject(ESODIUM,ERR_BAD_NONCE,nil);
    else {
        unsigned long clen = crypto_box_MACBYTES + dm.length;
        unsigned char *dc = (unsigned char *) sodium_malloc(clen);
        if (dc == NULL) reject(ESODIUM,ERR_FAILURE,nil);
        else {
            int result = crypto_box_easy(dc,[dm bytes], dm.length, [dn bytes], [dpk bytes], [dsk bytes]);
            if (result != 0)
                reject(ESODIUM,ERR_FAILURE,nil);
            else
                resolve([[NSData dataWithBytesNoCopy:dc length:clen freeWhenDone:NO]  base64EncodedStringWithOptions:0]);
            sodium_free(dc);
        }
    }
}

RCT_EXPORT_METHOD(crypto_box_easy_afternm:(NSString*)m n:(NSString*)n k:(NSString*)k resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dm = [[NSData alloc] initWithBase64EncodedString:m options:0];
    const NSData *dn = [[NSData alloc] initWithBase64EncodedString:n options:0];
    const NSData *dk = [[NSData alloc] initWithBase64EncodedString:k options:0];
    if (!dm || !dn || !dk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dk.length != crypto_box_SECRETKEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (dn.length != crypto_box_NONCEBYTES) reject(ESODIUM,ERR_BAD_NONCE,nil);
    else {
        unsigned long clen = crypto_box_MACBYTES + dm.length;
        unsigned char *dc = (unsigned char *) sodium_malloc(clen);
        if (dc == NULL) reject(ESODIUM,ERR_FAILURE,nil);
        else {
            int result = crypto_box_easy_afternm(dc, [dm bytes], dm.length, [dn bytes], [dk bytes]);
            if (result != 0)
                reject(ESODIUM,ERR_FAILURE,nil);
            else
                resolve([[NSData dataWithBytesNoCopy:dc length:clen freeWhenDone:NO]  base64EncodedStringWithOptions:0]);
            sodium_free(dc);
        }
    }
}

RCT_EXPORT_METHOD(crypto_box_open_easy:(NSString*)c n:(NSString*)n pk:(NSString*)pk sk:(NSString*)sk resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dc = [[NSData alloc] initWithBase64EncodedString:c options:0];
    const NSData *dn = [[NSData alloc] initWithBase64EncodedString:n options:0];
    const NSData *dpk = [[NSData alloc] initWithBase64EncodedString:pk options:0];
    const NSData *dsk = [[NSData alloc] initWithBase64EncodedString:sk options:0];
    if (!dc || !dn || !dpk || !dsk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dpk.length != crypto_box_PUBLICKEYBYTES || dsk.length != crypto_box_SECRETKEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (dn.length != crypto_box_NONCEBYTES) reject(ESODIUM,ERR_BAD_NONCE,nil);
    else if (crypto_box_open_easy([dc bytes], [dc bytes], dc.length, [dn bytes], [dpk bytes], [dsk bytes]) != 0)
        reject(ESODIUM,ERR_FAILURE,nil);
    else
        resolve([[NSData dataWithBytesNoCopy:[dc bytes] length:dc.length - crypto_box_MACBYTES freeWhenDone:NO]  base64EncodedStringWithOptions:0]);
}

RCT_EXPORT_METHOD(crypto_box_open_easy_afternm:(NSString*)c n:(NSString*)n k:(NSString*)k resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dc = [[NSData alloc] initWithBase64EncodedString:c options:0];
    const NSData *dn = [[NSData alloc] initWithBase64EncodedString:n options:0];
    const NSData *dk = [[NSData alloc] initWithBase64EncodedString:k options:0];
    if (!dc || !dn || !dk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dk.length != crypto_box_SECRETKEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (dn.length != crypto_box_NONCEBYTES) reject(ESODIUM,ERR_BAD_NONCE,nil);
    else if (crypto_box_open_easy_afternm([dc bytes], [dc bytes], dc.length, [dn bytes], [dk bytes]) != 0)
        reject(ESODIUM,ERR_FAILURE,nil);
    else
        resolve([[NSData dataWithBytesNoCopy:[dc bytes] length:dc.length - crypto_box_MACBYTES freeWhenDone:NO]  base64EncodedStringWithOptions:0]);
}

RCT_EXPORT_METHOD(crypto_box_beforenm:(NSString*)pk sk:(NSString*)sk resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dpk = [[NSData alloc] initWithBase64EncodedString:pk options:0];
    const NSData *dsk = [[NSData alloc] initWithBase64EncodedString:sk options:0];

    unsigned char *dshared = (unsigned char *) sodium_malloc(crypto_box_PUBLICKEYBYTES);
    if (!dpk || !dsk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dpk.length != crypto_box_PUBLICKEYBYTES || dsk.length != crypto_box_SECRETKEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (crypto_box_beforenm(dshared, [dpk bytes], [dsk bytes]) != 0)
        reject(ESODIUM,ERR_FAILURE,nil);
    else
        resolve([[NSData dataWithBytesNoCopy:dshared length:crypto_box_SECRETKEYBYTES freeWhenDone:NO] base64EncodedStringWithOptions:0]);
}

RCT_EXPORT_METHOD(crypto_box_seal:(NSString*)m pk:(NSString*)pk resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dm = [[NSData alloc] initWithBase64EncodedString:m options:0];
    const NSData *dpk = [[NSData alloc] initWithBase64EncodedString:pk options:0];
    unsigned long cipher_len = crypto_box_SEALBYTES + dm.length;
    unsigned char *dc = (unsigned char *) sodium_malloc(cipher_len);
    if (!dm || !dc) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dpk.length != crypto_sign_PUBLICKEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (crypto_box_seal(dc, [dm bytes], dm.length, [dpk bytes]) != 0)
        reject(ESODIUM,ERR_FAILURE,nil);
    else
        resolve([[NSData dataWithBytesNoCopy:dc length:cipher_len freeWhenDone:NO] base64EncodedStringWithOptions:0]);
}

RCT_EXPORT_METHOD(crypto_pwhash:(nonnull NSNumber*)keylen password:(NSString*)password salt:(NSString*)salt opslimit:(nonnull NSNumber*)opslimit memlimit:(nonnull NSNumber*)memlimit algo:(nonnull NSNumber*)algo resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dpassword = [password dataUsingEncoding:NSUTF8StringEncoding];
    const NSData *dsalt = [self hexToBin:salt];
    unsigned long long key_len = [keylen unsignedLongLongValue];
    unsigned char *key = (unsigned char *) sodium_malloc(key_len);

    if (crypto_pwhash(key, key_len,
                      [dpassword bytes],
                      [dpassword length],
                      [dsalt bytes],
                      [opslimit unsignedLongLongValue],
                      [memlimit unsignedLongValue], [algo intValue]) != 0)
        reject(ESODIUM, ERR_FAILURE, nil);
    else {
        NSData *result = [NSData dataWithBytesNoCopy:key length:key_len freeWhenDone:NO];
        resolve([self binToHex:result]);
    }
    sodium_free(key);

}

RCT_EXPORT_METHOD(crypto_box_seal_open:(NSString*)c pk:(NSString*)pk sk:(NSString*)sk resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dc = [[NSData alloc] initWithBase64EncodedString:c options:0];
    const NSData *dpk = [[NSData alloc] initWithBase64EncodedString:pk options:0];
    const NSData *dsk = [[NSData alloc] initWithBase64EncodedString:sk options:0];
    unsigned long cipher_len = dc.length - crypto_box_SEALBYTES;
    unsigned char *dm = (unsigned char *) sodium_malloc(cipher_len);
    if (!dc || !dpk || !dsk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dpk.length != crypto_box_PUBLICKEYBYTES || dsk.length != crypto_box_SECRETKEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (crypto_box_seal_open(dm, [dc bytes], dc.length, [dpk bytes], [dsk bytes]) != 0)
        reject(ESODIUM,ERR_FAILURE,nil);
    else
        resolve([[NSData dataWithBytesNoCopy:dm length:cipher_len freeWhenDone:NO] base64EncodedStringWithOptions:0]);
}

RCT_EXPORT_METHOD(crypto_scalarmult_base:(NSString*)n resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dn = [[NSData alloc] initWithBase64EncodedString:n options:0];
    unsigned char q[crypto_box_PUBLICKEYBYTES];
    if (!dn) reject(ESODIUM,ERR_FAILURE, nil);
    else if (dn.length != crypto_box_SECRETKEYBYTES) reject(ESODIUM, ERR_BAD_KEY, nil);
    else if (crypto_scalarmult_base(q, [dn bytes]) != 0)
        reject(ESODIUM,ERR_FAILURE, nil);
    else
        resolve([[NSData dataWithBytesNoCopy:q length:sizeof(q) freeWhenDone:NO] base64EncodedStringWithOptions:0]);
}

// *****************************************************************************
// * Public-key cryptography - signatures
// *****************************************************************************

RCT_EXPORT_METHOD(crypto_sign_detached:(NSString*)msg sk:(NSString*)sk resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dmsg = [[NSData alloc] initWithBase64EncodedString:msg options:0];
    const NSData *dsk  = [[NSData alloc] initWithBase64EncodedString:sk options:0];
    unsigned char *dsig = (unsigned char *) sodium_malloc(crypto_sign_BYTES);
    if (!dsig || !dmsg || !dsk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dsk.length != crypto_sign_SECRETKEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (crypto_sign_detached(dsig, nil, [dmsg bytes], dmsg.length, [dsk bytes]) != 0)
        reject(ESODIUM,ERR_FAILURE,nil);
    else
        resolve([[NSData dataWithBytesNoCopy:dsig length:crypto_sign_SECRETKEYBYTES freeWhenDone:NO]  base64EncodedStringWithOptions:0]);
    sodium_free(dsig);
}

RCT_EXPORT_METHOD(crypto_sign_verify_detached:(NSString*)sig msg:(NSString*)msg pk:(NSString*)pk resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dmsg = [[NSData alloc] initWithBase64EncodedString:msg options:0];
    const NSData *dpk  = [[NSData alloc] initWithBase64EncodedString:pk options:0];
    const NSData *dsig = [[NSData alloc] initWithBase64EncodedString:sig options:0];
    if (!dsig || !dmsg || !dpk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dpk.length != crypto_sign_PUBLICKEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (dsig.length != crypto_sign_BYTES) reject(ESODIUM,ERR_BAD_SIG,nil);
    else if (crypto_sign_verify_detached([dsig bytes], [dmsg bytes], dmsg.length, [dpk bytes]) != 0)
        reject(ESODIUM,ERR_FAILURE,nil);
    else
        resolve(@(TRUE));
}

RCT_EXPORT_METHOD(crypto_sign_keypair:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    unsigned char *sk = (unsigned char *) sodium_malloc(crypto_sign_SECRETKEYBYTES);
    unsigned char *pk = (unsigned char *) sodium_malloc(crypto_sign_PUBLICKEYBYTES);
    if (!sk || !pk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (crypto_sign_keypair(pk, sk) != 0)
        reject(ESODIUM,ERR_FAILURE,nil);
    else {
        NSString *pk64 = [[NSData dataWithBytesNoCopy:pk length:crypto_sign_PUBLICKEYBYTES freeWhenDone:NO]  base64EncodedStringWithOptions:0];
        NSString *sk64 = [[NSData dataWithBytesNoCopy:sk length:crypto_sign_SECRETKEYBYTES freeWhenDone:NO]  base64EncodedStringWithOptions:0];
        resolve(@{@"sk": sk64, @"pk": pk64});
    }
}

RCT_EXPORT_METHOD(crypto_sign_seed_keypair:(NSString*)seed resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dseed = [[NSData alloc] initWithBase64EncodedString:seed options:0];
    unsigned char *sk = (unsigned char *) sodium_malloc(crypto_sign_SECRETKEYBYTES);
    unsigned char *pk = (unsigned char *) sodium_malloc(crypto_sign_PUBLICKEYBYTES);
    if (!dseed || !sk || !pk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dseed.length != crypto_sign_SEEDBYTES) reject(ESODIUM,ERR_BAD_SEED,nil);
    else if (crypto_sign_seed_keypair(pk, sk, [dseed bytes]) != 0)
        reject(ESODIUM,ERR_FAILURE,nil);
    else {
        NSString *pk64 = [[NSData dataWithBytesNoCopy:pk length:crypto_sign_PUBLICKEYBYTES freeWhenDone:NO]  base64EncodedStringWithOptions:0];
        NSString *sk64 = [[NSData dataWithBytesNoCopy:sk length:crypto_sign_SECRETKEYBYTES freeWhenDone:NO]  base64EncodedStringWithOptions:0];
        resolve(@{@"sk": sk64, @"pk": pk64});
    }
}

RCT_EXPORT_METHOD(crypto_sign_ed25519_sk_to_seed:(NSString*)sk resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dsk = [[NSData alloc] initWithBase64EncodedString:sk options:0];
    unsigned char *seed = (unsigned char *) sodium_malloc(crypto_sign_SEEDBYTES);
    if (!seed || !dsk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (dsk.length != crypto_sign_SECRETKEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (crypto_sign_ed25519_sk_to_seed(seed, [dsk bytes]) != 0)
        reject(ESODIUM,ERR_FAILURE,nil);
    else {
        resolve([[NSData dataWithBytesNoCopy:seed length:crypto_sign_SEEDBYTES freeWhenDone:NO]  base64EncodedStringWithOptions:0]);
    }
}

RCT_EXPORT_METHOD(crypto_sign_ed25519_pk_to_curve25519:(NSString*)ed_pk resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *ded_pk = [[NSData alloc] initWithBase64EncodedString:ed_pk options:0];
    unsigned char *curve_pk = (unsigned char *) sodium_malloc(crypto_sign_PUBLICKEYBYTES);
    if (!ded_pk || !curve_pk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (ded_pk.length != crypto_sign_PUBLICKEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (crypto_sign_ed25519_pk_to_curve25519(curve_pk, [ded_pk bytes]) != 0)
        reject(ESODIUM,ERR_FAILURE,nil);
    else {
        resolve([[NSData dataWithBytesNoCopy:curve_pk length:crypto_sign_PUBLICKEYBYTES freeWhenDone:NO]  base64EncodedStringWithOptions:0]);
    }
}

RCT_EXPORT_METHOD(crypto_sign_ed25519_sk_to_curve25519:(NSString*)ed_sk resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *ded_sk = [[NSData alloc] initWithBase64EncodedString:ed_sk options:0];
    unsigned char *curve_sk = (unsigned char *) sodium_malloc(crypto_box_SECRETKEYBYTES);
    if (!ded_sk || !curve_sk) reject(ESODIUM,ERR_FAILURE,nil);
    else if (ded_sk.length != crypto_sign_SECRETKEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (crypto_sign_ed25519_sk_to_curve25519(curve_sk, [ded_sk bytes]) != 0)
        reject(ESODIUM,ERR_FAILURE,nil);
    else {
        resolve([[NSData dataWithBytesNoCopy:curve_sk length:crypto_box_SECRETKEYBYTES freeWhenDone:NO]  base64EncodedStringWithOptions:0]);
    }
}

RCT_EXPORT_METHOD(crypto_sign_ed25519_sk_to_pk:(NSString*)sk resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    const NSData *dsk = [[NSData alloc] initWithBase64EncodedString:sk options:0];
    unsigned char *pk = (unsigned char *) sodium_malloc(crypto_sign_PUBLICKEYBYTES);
    if (!dsk || !pk) reject(ESODIUM, ERR_FAILURE, nil);
    if (dsk.length != crypto_sign_SECRETKEYBYTES) reject(ESODIUM,ERR_BAD_KEY,nil);
    else if (crypto_sign_ed25519_sk_to_pk(pk, [dsk bytes]) != 0)
        reject(ESODIUM, ERR_FAILURE, nil);
    else {
        resolve([[NSData dataWithBytesNoCopy:pk length:crypto_sign_PUBLICKEYBYTES freeWhenDone:NO]  base64EncodedStringWithOptions:0]);
    }
}

// *****************************************************************************
// * Utils
// *****************************************************************************
RCT_EXPORT_METHOD(to_base64:(NSString*)message variant:(NSNumber * _Nonnull)variant resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    NSData *m = [message dataUsingEncoding:NSUTF8StringEncoding];

    if (m == nil || !variant) {
        reject(ESODIUM, ERR_FAILURE, nil);
    } else {
        NSString *encodedString = [self binToBase64:m variant:variant];
        if (encodedString == nil)
            reject(ESODIUM, ERR_FAILURE, nil);
        else {
            resolve(encodedString);
        }
    }
}

RCT_EXPORT_METHOD(from_base64:(NSString*)base64String variant:(NSNumber * _Nonnull)variant resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    if (!base64String || !variant) {
        reject(ESODIUM, ERR_FAILURE, nil);
    } else {
        NSData *result = [self base64ToBin:base64String variant:variant];
        if (result == nil)
            reject(ESODIUM, ERR_FAILURE, nil);
        else {
            NSString *decodedString = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
            resolve(decodedString);
        }
    }
}

RCT_EXPORT_METHOD(to_hex:(NSString*)message resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    NSData *m = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSString *result = [self binToHex:m];
    if (result == nil) reject(ESODIUM, ERR_FAILURE, nil);
    else {
        resolve(result);
    }
}

RCT_EXPORT_METHOD(from_hex:(NSString*)hexString resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    NSData *result = [self hexToBin:hexString];
    if (result == nil) reject(ESODIUM, ERR_FAILURE, nil);
    else {
        const NSString *res = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
        resolve(res);
    }
}

- (NSString *) binToBase64:(NSData*)bin variant:(NSNumber * _Nonnull)variant {
    if (!bin || !variant) return nil;

    else if (bin.length == 0) {
        return nil;
    } else {
        const size_t max_len = sodium_base64_encoded_len(bin.length, [variant intValue]);
        char * encoded = (char *) sodium_malloc(max_len);
        @try {
            sodium_bin2base64(encoded, max_len, [bin bytes], bin.length, [variant intValue]);
            NSString *res = [NSString stringWithCString:encoded encoding:NSUTF8StringEncoding];
            sodium_free(encoded);
            return res;
        }
        @catch (NSException *exception) {
            return nil;
        }
    }
}

- (NSData * __strong) base64ToBin:(NSString*)base64String variant:(NSNumber * _Nonnull)variant {
    const NSData *c = [base64String dataUsingEncoding:NSUTF8StringEncoding];

    if (c && variant) {

        // since libsodium doesn't provide the reverse of
        // sodium_base64_encoded_len(size_t bin_len, int variant)
        // to estimate bin_maxlen, we set it conservatively to
        // the size of the base64 representation

        size_t clen = [c length];
        unsigned char * const decoded = (unsigned char * const) sodium_malloc(clen);
        size_t decoded_len = [NSNumber numberWithLongLong: clen].unsignedLongLongValue;
        if (sodium_base642bin(decoded, clen, [c bytes], clen, NULL, &decoded_len, NULL, [variant intValue]) != 0) {
            sodium_free(decoded);
            return nil;
        }
        else {
            NSData *result = [NSData dataWithBytes:decoded length:decoded_len];
            sodium_free(decoded);
            return result;
        }
    }
    return nil;
}

- (NSString * __strong) binToHex:(NSData*)bin {
    size_t hex_maxlen = [bin length] * 2 + 1;
    char * const encoded = (char * const) sodium_malloc(hex_maxlen);
    @try {
        sodium_bin2hex(encoded, hex_maxlen, [bin bytes], [bin length]);
        NSString *result = [NSString stringWithCString:encoded encoding:NSUTF8StringEncoding];
        sodium_free(encoded);
        return result;
    }
    @catch (NSException *exception) {
        sodium_free(encoded);
        return nil;
    }
}

- (NSData * __strong) hexToBin:(NSString*)hexString {
    const NSData *h = [hexString dataUsingEncoding:NSUTF8StringEncoding];

    size_t clen = [h length];
    unsigned char * const decoded = (unsigned char * const) sodium_malloc(clen);
    size_t decoded_len = [NSNumber numberWithLongLong: clen].unsignedLongLongValue;
    if (sodium_hex2bin(decoded, clen, [h bytes], clen, NULL, &decoded_len, NULL) != 0) {
        sodium_free(decoded);
        return nil;
    }
    else {
        NSData *result = [NSData dataWithBytes:decoded length:decoded_len ];
        sodium_free(decoded);
        return result;
    }
}

@end
