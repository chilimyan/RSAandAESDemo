//
//  CLRSACryption.m
//  lkycareer
//
//  Created by Apple on 2017/4/6.
//  Copyright © 2017年 chilim. All rights reserved.
//

#import "CLRSACryption.h"
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>

#define kChosenDigestLength CC_SHA1_DIGEST_LENGTH

@implementation CLRSACryption{
    SecKeyRef _publicKey;
    SecKeyRef _privateKey;
    SecKeyRef _privateDecodeKey;
}


#pragma mark -

- (void)dealloc {
    !_publicKey ?: CFRelease(_publicKey);
    !_privateKey ?: CFRelease(_privateKey);
    !_privateDecodeKey ?: CFRelease(_privateDecodeKey);
}

- (SecKeyRef)getPublicKey {
    return _publicKey;
}

- (SecKeyRef)getPrivatKey {
    return _privateKey;
}

- (SecKeyRef)getPrivateDecodeKey {
    return _privateDecodeKey;
}

#pragma mark -获取公钥

- (void)loadPublicKeyFromFile:(NSString*)derFilePath {
    NSData *derData = [[NSData alloc] initWithContentsOfFile:derFilePath];
    [self loadPublicKeyFromData:derData];
}

- (void)loadPublicKeyFromData:(NSData*)derData {
    _publicKey = [self getPublicKeyRefrenceFromeData: derData];
}

#pragma mark -获取私钥

- (void)loadPrivateKeyFromFile:(NSString*)p12FilePath password:(NSString*)p12Password {
    NSData *p12Data = [NSData dataWithContentsOfFile:p12FilePath];
    [self loadPrivateKeyFromData:p12Data password:p12Password];
}
//解密的私钥，由于客户端与服务端交换了公钥，所以要用服务端的私钥解密
- (void)loadPrivateKeyDecodeFromFile:(NSString*)p12FilePath password:(NSString*)p12Password {
    NSData *p12Data = [NSData dataWithContentsOfFile:p12FilePath];
    [self loadPrivateKeyDecodeFromData:p12Data password:p12Password];
}

- (void)loadPrivateKeyFromData:(NSData*)p12Data password:(NSString*)p12Password {
    _privateKey = [self getPrivateKeyRefrenceFromData: p12Data password: p12Password];
}

- (void)loadPrivateKeyDecodeFromData:(NSData*)p12Data password:(NSString*)p12Password {
    _privateDecodeKey = [self getPrivateKeyRefrenceFromData: p12Data password: p12Password];
}


#pragma mark -

- (SecKeyRef)getPublicKeyRefrenceFromeData:(NSData*)derData {
    
    SecCertificateRef myCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)derData);
    SecPolicyRef myPolicy = SecPolicyCreateBasicX509();
    SecTrustRef myTrust;
    OSStatus status = SecTrustCreateWithCertificates(myCertificate,myPolicy,&myTrust);
    SecTrustResultType trustResult;
    if (status == noErr) {
        status = SecTrustEvaluate(myTrust, &trustResult);
    }
    SecKeyRef securityKey = SecTrustCopyPublicKey(myTrust);
    CFRelease(myCertificate);
    CFRelease(myPolicy);
    CFRelease(myTrust);
    
    return securityKey;
}

- (SecKeyRef)getPrivateKeyRefrenceFromData:(NSData*)p12Data password:(NSString*)password {
    
    SecKeyRef privateKeyRef = NULL;
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init];
    [options setObject: password forKey:(__bridge id)kSecImportExportPassphrase];
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus securityError = SecPKCS12Import((__bridge CFDataRef) p12Data, (__bridge CFDictionaryRef)options, &items);
    if (securityError == noErr && CFArrayGetCount(items) > 0) {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
        securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
        if (securityError != noErr) {
            privateKeyRef = NULL;
        }
    }
    CFRelease(items);
    
    return privateKeyRef;
}

#pragma mark -

- (NSData*)rsaEncryptString:(NSString*)string {
    NSData* data = [string dataUsingEncoding:NSUTF8StringEncoding];
    NSData* encryptedData = [self rsaEncryptData: data];
//    NSString *base64EncryptedString = [GTMBase64 stringByEncodingData:encryptedData];
    return encryptedData;
}


- (NSData*)rsaEncryptData:(NSData*)data {
    
    SecKeyRef key = [self getPublicKey];
    size_t cipherBufferSize = SecKeyGetBlockSize(key);
    uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    size_t blockSize = cipherBufferSize - 11;
    size_t blockCount = (size_t)ceil([data length] / (double)blockSize);
    
    NSMutableData *encryptedData = [[NSMutableData alloc] init];
    
    for (int i=0; i<blockCount; i++) {
        unsigned long bufferSize = MIN(blockSize , [data length] - i * blockSize);
        NSData *buffer = [data subdataWithRange:NSMakeRange(i * blockSize, bufferSize)];
        OSStatus status = SecKeyEncrypt(key,
                                        kSecPaddingPKCS1,
                                        (const uint8_t *)[buffer bytes],
                                        [buffer length],
                                        cipherBuffer,
                                        &cipherBufferSize);
        
        if (status != noErr) {
            return nil;
        }
        
        NSData *encryptedBytes = [[NSData alloc] initWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
        [encryptedData appendData:encryptedBytes];
    }
    
    if (cipherBuffer){
        free(cipherBuffer);
    }
    
    return encryptedData;
}


#pragma mark -

- (NSString*)rsaDecryptString:(NSString*)string {
    
    NSData* data = [[NSData alloc] initWithBase64EncodedString:string options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData* decryptData = [self rsaDecryptData:data];
    NSString* result = [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding];
    return result;
}

- (NSData*)rsaDecryptData:(NSData*)data {
    SecKeyRef key = [self getPrivateDecodeKey];
    
    size_t cipherBufferSize = SecKeyGetBlockSize(key);
    size_t blockSize = cipherBufferSize;
    size_t blockCount = (size_t)ceil([data length] / (double)blockSize);
    
    NSMutableData *decryptedData = [[NSMutableData alloc] init];
    
    for (int i = 0; i < blockCount; i++) {
        unsigned long bufferSize = MIN(blockSize , [data length] - i * blockSize);
        NSData *buffer = [data subdataWithRange:NSMakeRange(i * blockSize, bufferSize)];
        
        size_t cipherLen = [buffer length];
        void *cipher = malloc(cipherLen);
        [buffer getBytes:cipher length:cipherLen];
        size_t plainLen = SecKeyGetBlockSize(key);
        void *plain = malloc(plainLen);
        
        OSStatus status = SecKeyDecrypt(key, kSecPaddingPKCS1, cipher, cipherLen, plain, &plainLen);
        
        if (status != noErr) {
            return nil;
        }
        
        NSData *decryptedBytes = [[NSData alloc] initWithBytes:(const void *)plain length:plainLen];
        [decryptedData appendData:decryptedBytes];
    }
    
    return decryptedData;
}

#pragma mark -

- (NSData *)rsaSHA256SignData:(NSData *)plainData {
    SecKeyRef key = [self getPrivatKey];
    
    size_t signedHashBytesSize = SecKeyGetBlockSize(key);
    uint8_t* signedHashBytes = malloc(signedHashBytesSize);
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return nil;
    }
    
    SecKeyRawSign(key,
                  kSecPaddingPKCS1SHA256,
                  hashBytes,
                  hashBytesSize,
                  signedHashBytes,
                  &signedHashBytesSize);
    
    NSData* signedHash = [NSData dataWithBytes:signedHashBytes
                                        length:(NSUInteger)signedHashBytesSize];
    
    if (hashBytes)
        free(hashBytes);
    if (signedHashBytes)
        free(signedHashBytes);
    
    return signedHash;
}
- (NSData*)getHashBytes:(NSData*)plainText {
    
    CC_SHA1_CTX ctx;
    
    uint8_t* hashBytes =NULL;
    
    NSData* hash =nil;
    
    // Malloc a buffer to hold hash.
    
    hashBytes =malloc(kChosenDigestLength*sizeof(uint8_t) );
    
    memset((void*)hashBytes,0x0,kChosenDigestLength);
    
    // Initialize the context.
    
    CC_SHA1_Init(&ctx);
    
    // Perform the hash.
    
    CC_SHA1_Update(&ctx, (void*)[plainText bytes], (CC_LONG)[plainText length]);
    
    // Finalize the output.
    
    CC_SHA1_Final(hashBytes, &ctx);
    
    // Build up the SHA1 blob.
    
    hash = [NSData dataWithBytes:(const void *)hashBytes length:(NSUInteger)kChosenDigestLength];
    
    if(hashBytes)free(hashBytes);
    
    return hash;
    
}

//SHA256签名
- (NSData *)sha256WithRSA:(NSData *)plainData {
    SecKeyRef privateKey = [self getPrivatKey];
    return [self sha256WithRSA:plainData privateKey:privateKey];
}
//SHA1WhithRSA签名
- (NSData *)sha1WithRSA:(NSData *)plainData{
    SecKeyRef privateKey = [self getPrivatKey];
    return [self sha1WithRSA:plainData privateKey:privateKey];
}
- (NSData *)sha1WithRSA:(NSData *)plainData privateKey:(SecKeyRef)privateKey {
   
    size_t cipherBufferSize = SecKeyGetBlockSize(privateKey);
    
    uint8_t* signedBytes = malloc( cipherBufferSize * sizeof(uint8_t) ); // Malloc a buffer to hold signature.
    memset((void *)signedBytes, 0x0, cipherBufferSize);
    
    uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    
    NSData *encryptedData = [[NSData alloc] init] ;
   
    OSStatus status = SecKeyRawSign(privateKey,
                                    kSecPaddingPKCS1SHA1,
                                    (const uint8_t *)[[self getHashBytes:plainData] bytes],
                                    kChosenDigestLength,
                                    (uint8_t *)signedBytes,
                                    &cipherBufferSize);
    if (status == noErr){
        encryptedData = [NSData dataWithBytes:(const void*)signedBytes length:(NSUInteger)cipherBufferSize];
    }else{
        if (cipherBuffer) {
            free(cipherBuffer);
        }
        return nil;
    }
    
    if (cipherBuffer){
        free(cipherBuffer);
    }
    return encryptedData;
}


- (NSData *)sha256WithRSA:(NSData *)plainData privateKey:(SecKeyRef)privateKey {
    
    size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey);
    uint8_t* signedHashBytes = malloc(signedHashBytesSize);
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return nil;
    }
    
    SecKeyRawSign(privateKey,
                  kSecPaddingPKCS1SHA256,
                  hashBytes,
                  hashBytesSize,
                  signedHashBytes,
                  &signedHashBytesSize);
    
    NSData* signedHash = [NSData dataWithBytes:signedHashBytes
                                        length:(NSUInteger)signedHashBytesSize];
    
    if (hashBytes)
        free(hashBytes);
    if (signedHashBytes)
        free(signedHashBytes);
    
    return signedHash;
}

- (BOOL)rsaSHA256VertifyingData:(NSData *)plainData withSignature:(NSData *)signature {
    SecKeyRef publicKey = [self getPublicKey];
    return [self rsaSHA256VertifyingData:plainData withSignature:signature publicKey:publicKey];
}

- (BOOL)rsaSHA256VertifyingData:(NSData *)plainData withSignature:(NSData *)signature publicKey:(SecKeyRef)publicKey {
    size_t signedHashBytesSize = SecKeyGetBlockSize(publicKey);
    const void* signedHashBytes = [signature bytes];
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return NO;
    }
    
    OSStatus status = SecKeyRawVerify(publicKey,
                                      kSecPaddingPKCS1SHA256,
                                      hashBytes,
                                      hashBytesSize,
                                      signedHashBytes,
                                      signedHashBytesSize);
    
    return status == errSecSuccess;
}


@end
