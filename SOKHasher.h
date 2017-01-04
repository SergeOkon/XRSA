//
//  SOKHasher.h
//
//  Created by Serge Okon on 2017-01-03.
//  Copyright © 2017 Momentus Software. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, SOKHasherHashFunc) {
    SOKHasher_MD5_UNSECURE     = 1000, // The UNSECURE part is just a reminder not to use MD5 any longer, unless one really must. Collisions have been created for MD5 already, rendering it non-secure.
    SOKHasher_SHA1,                   // SHA-1 is also becoming more suspect...
    SOKHasher_SHA224,                 // SHA-2 algorithms here and below are the suggested hash types.
    SOKHasher_SHA256,
    SOKHasher_SHA384,
    SOKHasher_SHA512,
};


@interface SOKHasher : NSObject

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
