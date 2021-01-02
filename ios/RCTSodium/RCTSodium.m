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
