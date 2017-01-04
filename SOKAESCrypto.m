//
//  SOKAESCrypto.m
//  xrsa-test
//
//  Created by Serge Okon on 2017-01-03.
//  Copyright © 2017 Serge Okon. All rights reserved.
//

#import "CommonCrypto/CommonCryptor.h"
#import "SOKAESCrypto.h"

@implementation SOKAESCrypto


+(NSData *) oneShotOperation:(CCOperation)operation
                        data:(NSData *)data
                         key:(NSData *)key
                          iv:(NSData *)iv
{
    // Sanity Checks
    if (!data || !key) {
        NSLog(@"SOKAESCrypto: Either no data or not key was given.");
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
    return [SOKAESCrypto oneShotOperation:kCCEncrypt data:plainText key:keyData iv:ivData];
}

+(NSData *) decrypt:(NSData *)chiperData
                key:(NSData *)keyData
                 iv:(NSData *)ivData
{
    return [SOKAESCrypto oneShotOperation:kCCDecrypt data:chiperData key:keyData iv:ivData];
}


@end
