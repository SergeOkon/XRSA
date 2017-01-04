//
//  SOKRandom.m
//  xrsa-test
//
//  Created by Serge Okon on 2017-01-03.
//  Copyright © 2017 Momentus Software. All rights reserved.
//

#import "SOKRandom.h"

@implementation SOKRandom

+(NSData *) secRandomBytes:(NSUInteger)length
{
    void* buf = malloc(length);
    int result = SecRandomCopyBytes(kSecRandomDefault, length, buf);
    if (result == 0) {
        // Success!
        return [NSData dataWithBytesNoCopy:buf length:length];
    } else {
        NSLog(@"SecRandomCopyBytes could not generate random data, errno is: %d", (int) errno);
        return nil;
    }
}


@end
