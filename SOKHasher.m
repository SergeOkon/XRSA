//
//  SOKHasher.m
//
//  Created by Serge Okon on 2017-01-03.
//  Copyright © 2017 Momentus Software. All rights reserved.
//

#import "SOKHasher.h"
#include <CommonCrypto/CommonDigest.h>

@interface SOKHasher()

@property (nonatomic) SOKHasherHashFunc hashFunc;
@property (nonatomic) NSUInteger hashLength;

// State and Function pointers
@property (nonatomic) void* hashStateStructure;
@property (nonatomic) int (*hashInitFunc)(void *ctx);
@property (nonatomic) int (*hashUpdateFunc)(void *ctx, const void *data, CC_LONG len);
@property (nonatomic) int (*hashFinalFunc)(unsigned char *md, void *ctx);
@end

@implementation SOKHasher : NSObject

-(instancetype)initWithFunc:(SOKHasherHashFunc)hashFunction
{
    // Sanity Check - update these as we implement new hashing function.
    if (hashFunction < SOKHasher_MD5_UNSECURE || hashFunction > SOKHasher_SHA512) {
        return nil;
    }
    
    // Initializes
    self = [super init];
    if (self) {
        _hashFunc = hashFunction;
        [self setUpPointersForAlgorithm];
        
    }
    return self;
}

// CommonCrypto's function are types are well named, so we are able to to generate our setUpPointersForAlgorithm
//  code with a template.
#define SOK_GenerateContextAndFunctionsForHashFunction(func, ctx) \
    _hashStateStructure = malloc(sizeof(CC_ ## ctx ## _CTX));                                    \
    _hashInitFunc   = (int(*)(void *ctx)) CC_ ## func ## _Init;                                  \
    _hashUpdateFunc = (int(*)(void *ctx, const void *data, CC_LONG len)) CC_ ## func ## _Update; \
    _hashFinalFunc  = (int(*)(unsigned char *md, void *ctx)) CC_ ## func ## _Final;              \
    _hashLength     = CC_ ## func ## _DIGEST_LENGTH


-(void) setUpPointersForAlgorithm
{
    // Reset the values first
    if (_hashStateStructure) {
        free(_hashStateStructure);
    }
    _hashInitFunc = 0;
    _hashUpdateFunc = 0;
    _hashFinalFunc = 0;
    
    // Then set them up based on the algorithm
    switch (_hashFunc) {
        case SOKHasher_MD5_UNSECURE:
            SOK_GenerateContextAndFunctionsForHashFunction(/*function*/ MD5,
                                                           /*ctx used*/ MD5);
            break;
        case SOKHasher_SHA1:
            SOK_GenerateContextAndFunctionsForHashFunction(/*function*/ SHA1,
                                                           /*CTX used*/ SHA1);
            break;
        case SOKHasher_SHA224:
            SOK_GenerateContextAndFunctionsForHashFunction(/*function*/ SHA224,
                                                           /*CTX used*/ SHA256);
            break;
        case SOKHasher_SHA256:
            SOK_GenerateContextAndFunctionsForHashFunction(/*function*/ SHA256,
                                                           /*CTX used*/ SHA256);
            break;
        case SOKHasher_SHA384:
            SOK_GenerateContextAndFunctionsForHashFunction(/*function*/ SHA384,
                                                           /*CTX used*/ SHA512);
            break;
        case SOKHasher_SHA512:
            SOK_GenerateContextAndFunctionsForHashFunction(/*function*/ SHA512,
                                                           /*CTX used*/ SHA512);
            break;
        default:
            break;
    }
}


-(NSData *)hash:(NSData*)data
{
    _hashInitFunc(self.hashStateStructure);
    _hashUpdateFunc(self.hashStateStructure, [data bytes], (CC_LONG) [data length]);
    void *md = malloc(self.hashLength);
    _hashFinalFunc(md, self.hashStateStructure);
    return [NSData dataWithBytesNoCopy:md length:self.hashLength];
}

-(void)startHash
{
    _hashInitFunc(self.hashStateStructure);
}

-(void)enterData:(NSData *)data;
{
    _hashUpdateFunc(self.hashStateStructure, [data bytes], (CC_LONG) [data length]);
}

-(NSData *)completeHash
{
    void* md = malloc((CC_LONG) self.hashLength);
    _hashFinalFunc(md, self.hashStateStructure);
    return [NSData dataWithBytesNoCopy:md length:self.hashLength];
}

-(void) dealloc
{
    if (_hashStateStructure) {
        free(_hashStateStructure);
        _hashStateStructure = 0;
    }
}


@end
