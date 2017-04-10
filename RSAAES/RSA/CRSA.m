//
//  CRSA.m
//  AES_RSA
//
//  Created by StephenZhu on 15/8/27.
//  Copyright (c) 2015年 StephenZhu. All rights reserved.
//该类是使用第三发Openssl库进行RSA加密

#import "CRSA.h"
#import "CLRSACryption.h"
#import "SBJson.h"
#import "NSData+AES256.h"
#define BUFFSIZE  1024
#import "GTMBase64.h"
#define PADDING RSA_PKCS1_PADDING


@implementation CRSA

+ (id)shareInstance
{
    static CRSA *_crsa = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _crsa = [[self alloc] init];
    });
    return _crsa;
}

/**
 *  随机生成16位
 *
 *  @param size 1
 *
 *  @return 1
 */

-(NSString *)set32bitString:(int)size

{
    char data[size];
    for (int x=0;x<size;x++)
    {
        int randomint = arc4random_uniform(2);
        if (randomint == 0) {
            data[x] = (char)('A' + (arc4random_uniform(26)));
        }
        else
        {
            data[x] = (char)('0' + (arc4random_uniform(9)));
        }
        
    }
    
    return [[NSString alloc] initWithBytes:data length:size encoding:NSUTF8StringEncoding];
}


/**
 此处RSA加密是用系统security.framework框架
 @param dic <#dic description#>
 @return <#return value description#>
 */
- (NSDictionary*)rsa_aes{
    NSDictionary *dic = @{@"mobile":@"13888888888"
                          };
    
    CLRSACryption *rsa = [CLRSACryption new];
    //导入公钥
    NSString *derPath = [[NSBundle mainBundle] pathForResource:@"public_key_s" ofType:@"der"];
    [rsa loadPublicKeyFromFile:derPath];
    //导入私钥
    NSString *p12Path = [[NSBundle mainBundle] pathForResource:@"private_key_c" ofType:@"p12"];
    [rsa loadPrivateKeyFromFile:p12Path password:@"1234"];
    
    //导入解密私钥
    NSString *p12PathDecode = [[NSBundle mainBundle] pathForResource:@"private_key_s" ofType:@"p12"];
    [rsa loadPrivateKeyDecodeFromFile:p12PathDecode password:@"1234"];

    
    SBJsonWriter * parser = [[SBJsonWriter alloc]init];
    NSString *realString = [parser stringWithObject:dic];
    //签名
    NSData *signedData = [rsa sha1WithRSA:[realString dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *sign = [GTMBase64 stringByEncodingData:signedData];
    
    //16位随机数
    NSString *merchantAesKey = [self set32bitString:16];
    //16位随机数和json字符串用AES加密
    NSString *aesdata = [NSData AES128EncryptWithPlainText:realString key:merchantAesKey];
    //16位随机数和公钥用RSA加密
    NSString *Stringencryptkey =[GTMBase64 stringByEncodingData:[rsa rsaEncryptString:merchantAesKey]];
    
    NSDictionary *input_params = @{@"params":aesdata,
                                   @"encryptKey":Stringencryptkey,
                                   @"sign":sign
                                   };
    //========解密======//
    
    NSString *decodeEncrpy = [rsa rsaDecryptString:Stringencryptkey];
    NSString *StringybRealData = [NSData AES128DecryptWithCiphertext:aesdata key:decodeEncrpy];
    NSLog(@"解密：===随机数=%@====密文=%@",decodeEncrpy,StringybRealData);
    return input_params;
}


- (BOOL)importRSAKeyWithType:(KeyType)type
{
    FILE *file;
    NSString *keyName = type == KeyTypePublic ? @"rsa_public_key" : @"rsa_private_key";
    NSString *keyPath = [[NSBundle mainBundle] pathForResource:keyName ofType:@"pem"];
    
    file = fopen([keyPath UTF8String], "rb");
    
    if (NULL != file)
    {
        if (type == KeyTypePublic)
        {
            _rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
            assert(_rsa != NULL);
        }
        else
        {
            _rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
            assert(_rsa != NULL);
        }
        
        fclose(file);
        
        return (_rsa != NULL) ? YES : NO;
    }
    
    return NO;
}

- (NSString *)signString:(NSString *)string withKeyType:(KeyType)keyType
{
    if (![self importRSAKeyWithType:keyType])
        return nil;
    const char *message = [string cStringUsingEncoding:NSUTF8StringEncoding];
    int messageLength = (int)strlen(message);
    unsigned char *sig = (unsigned char *)malloc(256);
    unsigned int sig_len;
    
    unsigned char sha1[20];
    SHA1((unsigned char *)message, messageLength, sha1);
    
    int rsa_sign_valid = RSA_sign(NID_sha1
                                  , sha1, 20
                                  , sig, &sig_len
                                  , _rsa);
    if (rsa_sign_valid == 1) {
        NSData* data = [NSData dataWithBytes:sig length:sig_len];
        
        NSString * base64String = [data base64EncodedStringWithOptions:0];
        free(sig);
        return base64String;
    }
    
    free(sig);
    return nil;
}


- (NSString *) encryptByRsa:(NSString*)content withKeyType:(KeyType)keyType
{
    if (![self importRSAKeyWithType:keyType])
        return nil;
    int status;
    int length  = (int)[content length];
    unsigned char input[length + 1];
    bzero(input, length + 1);
    int i = 0;
    for (; i < length; i++)
    {
        input[i] = [content characterAtIndex:i];
    }
    NSInteger  flen = [self getBlockSizeWithRSA_PADDING_TYPE:PADDING];
    char *encData = (char*)malloc(flen);
    bzero(encData, flen);
    switch (keyType) {
        case KeyTypePublic:
            status = RSA_public_encrypt(length, (unsigned char*)input, (unsigned char*)encData, _rsa, PADDING);
            break;
            
        default:
            status = RSA_private_encrypt(length, (unsigned char*)input, (unsigned char*)encData, _rsa, PADDING);
            break;
    }
    if (status)
    {
        NSData *returnData = [NSData dataWithBytes:encData length:status];
        free(encData);
        encData = NULL;
        
        NSString *ret = [GTMBase64 stringByEncodingData:returnData];
        return ret;
    }
    free(encData);
    encData = NULL;
    return nil;
}

- (NSString *) decryptByRsa:(NSString*)content withKeyType:(KeyType)keyType
{
    if (![self importRSAKeyWithType:keyType])
        return nil;
    int status;
    NSData *data = [GTMBase64 decodeString:content];
    int length = (int)[data length];
    NSInteger flen = [self getBlockSizeWithRSA_PADDING_TYPE:PADDING];
    char *decData = (char*)malloc(flen);
    bzero(decData, flen);
    switch (keyType) {
        case KeyTypePublic:
            status = RSA_public_decrypt(length, (unsigned char*)[data bytes], (unsigned char*)decData, _rsa, PADDING);
            break;
            
        default:
            status = RSA_private_decrypt(length, (unsigned char*)[data bytes], (unsigned char*)decData, _rsa, PADDING);
            break;
    }
    if (status){
        NSMutableString *decryptString = [[NSMutableString alloc] initWithBytes:decData length:strlen(decData) encoding:NSUTF8StringEncoding];
        free(decData);
        decData = NULL;
        
        return decryptString;
    }
    free(decData);
    decData = NULL;
    return nil;
}

- (int)getBlockSizeWithRSA_PADDING_TYPE:(RSA_PADDING_TYPE)padding_type
{
    int len = RSA_size(_rsa);
    
    if (padding_type == RSA_PADDING_TYPE_PKCS1 || padding_type == RSA_PADDING_TYPE_SSLV23) {
        len -= 11;
    }
    
    return len;
}

@end
