//
//  SOKAES.m
//  xrsa-test
//
//  Created by Serge Okon on 2017-01-03.
//  Copyright © 2017 Serge Okon. All rights reserved.
//

#import "CommonCrypto/CommonCryptor.h"
#import "SOKAES.h"


@interface SOKAES()
@property CCCryptorRef aesCryptorRef;
@property CCOperation operation;
@end

@implementation SOKAES

// One Shot operations don't need state - thus are class methods
+(NSData *) oneShotOperation:(CCOperation)operation
                        data:(NSData *)data
                         key:(NSData *)key
                          iv:(NSData *)iv
{
    // Sanity Checks
    if (!data || !key) {
        NSLog(@"SOKAESCrypto: Either no data or no key was given.");
        return nil;       // No data given, or no key given.
    }
    
    if (iv && [iv length] != kCCBlockSizeAES128) {
       NSLog(@"SOKAESCrypto: IV's passed in, but were not 16 bytes long, %ld bytes intead", (long)[iv length]);
       return nil; // Iv was given, but not of appropriate ,size
    }
    
    if ([key length] != 16 && [key length] != 24 && [key length] != 32) {
        NSLog(@"SOKAESCrypto: Only AES key sizes of 128, 192, 256 bits are supported.");
        return nil;
    }
    
    size_t maxDataSizeOut = [data length] + kCCBlockSizeAES128;
    size_t dataSizeOut = 0;
    void* dataOut = malloc(maxDataSizeOut);
    CCCryptorStatus result =
        CCCrypt(operation, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                [key bytes], [key length], [iv bytes], [data bytes],
                [data length], dataOut, maxDataSizeOut, &dataSizeOut);
    
    if (result == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:dataOut length:dataSizeOut];
    } else {
        NSLog(@"CCCrypt %s failure, code: %ld",
              (operation == kCCEncrypt ? "encrypt" : "decrypt"),
              (long)result);
        return nil;
    }
}


+(NSData *) encrypt:(NSData *)plainText
                key:(NSData *)keyData
                iv:(NSData *)ivData
{
    return [SOKAES oneShotOperation:kCCEncrypt data:plainText key:keyData iv:ivData];
}

+(NSData *) decrypt:(NSData *)chiperData
                key:(NSData *)keyData
                 iv:(NSData *)ivData
{
    return [SOKAES oneShotOperation:kCCDecrypt data:chiperData key:keyData iv:ivData];
}

// Encrypting a stream of data needs state - so there are object methods

-(instancetype)initWithOperation:(CCOperation)operation
                             key:(NSData *)keyData
                              iv:(NSData *)ivData
{
     // Sanity Checks
    if (!keyData) {
        NSLog(@"SOKAESCrypto: No key was given.");
        return nil;       // No data given, or no key given.
    }
    
    if (ivData && [ivData length] != kCCBlockSizeAES128) {
        NSLog(@"SOKAESCrypto: IV's passed in, but were not 16 bytes long, %ld bytes intead", (long)[ivData length]);
        return nil; // Iv was given, but not of appropriate ,size
    }
    
    if ([ivData length] != 16 && [ivData length] != 24 && [ivData length] != 32) {
        NSLog(@"SOKAESCrypto: Only AES key sizes of 128, 192, 256 bits are supported.");
        return nil;
    }
    
    self = [super init];
    if (self) {
        _aesCryptorRef = 0;
        _operation = operation;
        CCCryptorStatus status = CCCryptorCreate(operation, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                                                 [keyData bytes], [keyData length], [ivData bytes], &_aesCryptorRef);
        if (status != kCCSuccess)
        {
            NSLog(@"CCCryptorCreate for %s failure, code: %ld",
                  (operation == kCCEncrypt ? "encrypt" : "decrypt"),
                  (long)status);
            return nil;
        }
    }
    
    return self;
}


-(instancetype)initEncryptionWithKey:(NSData *)keyData
                                  iv:(NSData *)ivData
{
    return [self initWithOperation:kCCEncrypt key:keyData iv:ivData];
}

-(instancetype)initDecryptionWithKey:(NSData *)keyData
                                  iv:(NSData *)ivData
{
    return [self initWithOperation:kCCDecrypt key:keyData iv:ivData];
}

-(NSData *)processData:(NSData *)data
{
    // Sanity check
    if (!self.aesCryptorRef) return nil;
    
    size_t dataOutAvailable = CCCryptorGetOutputLength(self.aesCryptorRef, [data length], false);
    void *output = malloc(dataOutAvailable);
    size_t dataOutMoved = 0;
    CCCryptorStatus status = CCCryptorUpdate(self.aesCryptorRef, [data bytes], [data length], output, dataOutAvailable, &dataOutMoved);
    if (status == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:output length:dataOutMoved];
    } else {
        NSLog(@"CCCryptorUpdate %s failure, code: %ld",
              (self.operation == kCCEncrypt ? "encrypt" : "decrypt"),
              (long)status);
        return nil;
    }
}

-(NSData *)flushAndFinish
{
    if (!self.aesCryptorRef) return nil;
    
    size_t dataOutAvailable = CCCryptorGetOutputLength(self.aesCryptorRef, 0, true);
    void *output = malloc(dataOutAvailable);
    size_t dataOutMoved = 0;
    CCCryptorStatus status = CCCryptorFinal(self.aesCryptorRef, output, dataOutAvailable, &dataOutMoved);
    if (status == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:output length:dataOutAvailable];
    } else {
        NSLog(@"CCCryptorFinal %s failure, code: %ld",
              (_operation == kCCEncrypt ? "encrypt" : "decrypt"),
              (long)status);
        return nil;
    }
}

-(void)dealloc
{
    if (_aesCryptorRef) {
        CCCryptorRelease(_aesCryptorRef);
        _aesCryptorRef = 0;
    }
}


@end
