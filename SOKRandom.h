//
//  SOKRandom.h
//  xrsa-test
//
//  Created by Serge Okon on 2017-01-03.
//  Copyright © 2017 Momentus Software. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SOKRandom : NSObject

// Generates a Cryptographically secure random NSData object of the specified size in bytes
+(NSData * _Nullable) secRandomBytes:(NSUInteger)length;

@end
