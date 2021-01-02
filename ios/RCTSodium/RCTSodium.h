#import <Foundation/Foundation.h>

@interface RCTSodium : NSObject <RCTBridgeModule>

- (void) sodium_version_string:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject;

- (void) randombytes_random:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject;
- (void) randombytes_buf:(NSUInteger)size resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject;

- (void) crypto_pwhash:(NSNumber*)keylen password:(NSString*)password salt:(NSString*)salt opslimit:(NSNumber*)opslimit memlimit:(NSNumber*)memlimit algo:(NSNumber*)algo resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject;

- (void) crypto_aead_xchacha20poly1305_ietf_encrypt:(NSString*)message public_nonce:(NSString*)public_nonce key:(NSString*)key additionalData:(NSString*)additionalData resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject;
- (void) crypto_aead_xchacha20poly1305_ietf_decrypt:(NSString*)cipherText public_nonce:(NSString*)public_nonce key:(NSString*)key additionalData:(NSString*)additionalData resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject;
- (void) crypto_aead_xchacha20poly1305_ietf_keygen:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject;

- (void) to_base64:(NSString*)message variant:(NSNumber*)variant resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject;
- (void) from_base64:(NSString*)cipher variant:(NSNumber*)variant resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject;

- (void) to_hex:(NSString*)message resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject;
- (void) from_hex:(NSString*)cipher resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject;

@end
