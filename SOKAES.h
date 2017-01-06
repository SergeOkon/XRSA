//
//  SOKAES.h
//  xrsa-test
//
//  Created by Serge Okon on 2017-01-03.
//  Copyright © 2017 Serge Okon. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SOKAES : NSObject

// One Shot operations don't need state - thus are class methods

+(NSData * _Nullable) encrypt:(NSData * _Nonnull)plainText
                          key:(NSData * _Nonnull)keyData    // Don't re-use the same key for multiple calls, unless you use a random IV for each one.
                           iv:(NSData * _Nullable)ivData;   // Optional, but don't encrypt more than once with your key if this is nil, or if your key is not random.

+(NSData * _Nullable) decrypt:(NSData * _Nonnull)chiperData
                          key:(NSData * _Nonnull)keyData
                           iv:(NSData * _Nullable)ivData;


//

-(instancetype _Nullable)initEncryptionWithKey:(NSData * _Nonnull)keyData
                                                // Don't re-use the same key for multiple calls,
                                                //  unless you use a securely-random IV for each operation.
                                            iv:(NSData * _Nullable)ivData;
                                                // Optional, but don't encrypt more than once with your key
                                                //  if you pass nil for iv, or if your key is not random.

-(instancetype _Nullable)initDecryptionWithKey:(NSData * _Nonnull)keyData
                                            iv:(NSData * _Nullable)ivData;


-(NSData * _Nullable)processData:(NSData * _Nonnull)data;
-(NSData * _Nullable)flushAndFinish;


@end
