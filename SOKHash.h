//
//  SOK_Hasher.h
//
//  Created by Serge Okon on 2017-01-03.
//  Copyright © 2017 Momentus Software. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, SOKHasherHashFunc) {
    SOKHash_MD5_UNSECURE     = 1000, // The UNSECURE part is just a reminder not to use MD5 any longer, unless one really must. Collisions have been created for MD5 already, rendering it non-secure.
    SOKHash_SHA1,                   // SHA-1 is also becoming more suspect...
    SOKHash_SHA224,                 // SHA-2 algorithms here and below are the suggested hash types.
    SOKHash_SHA256,
    SOKHash_SHA384,
    SOKHash_SHA512,
};


@interface SOKHash : NSObject

@property (nonatomic, readonly) SOKHasherHashFunc hashFunc;
@property (nonatomic, readonly) NSUInteger hashLength;

-(instancetype _Nullable)initWithFunc:(SOKHasherHashFunc)hashFunction;

// Just get a hash value quickly.
-(NSData *_Nonnull) hash:(NSData* _Nonnull)data;

// If you'd like to stream the data
-(void) startHash;
-(void) enterData:(NSData * _Nonnull)data;
-(NSData * _Nonnull) completeHash;  // Returns the has value

@end
