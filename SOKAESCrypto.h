//
//  SOKAESCrypto.h
//  xrsa-test
//
//  Created by Serge Okon on 2017-01-03.
//  Copyright © 2017 Serge Okon. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SOKAESCrypto : NSObject


+(NSData * _Nullable) encrypt:(NSData * _Nonnull)plainText
                          key:(NSData * _Nonnull)keyData    // Don't re-use the same key for multiple calls, unless you use a random IV for each one.
                           iv:(NSData * _Nullable)ivData;   // Optional, but don't encrypt more than once with your key if this is nil, or if your key is not random.

+(NSData * _Nullable) decrypt:(NSData * _Nonnull)chiperData
                          key:(NSData * _Nonnull)keyData
                           iv:(NSData * _Nullable)ivData;


@end
