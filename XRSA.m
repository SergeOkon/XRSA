#import "XRSA.h"

@interface XRSA ()
@property (nonatomic) NSNumber *keyLength;
@property (nonatomic) SecKeyRef publicKey;

@end

@implementation XRSA

- (XRSA *)initWithDERData:(NSData *)keyData {
    self = [super init];

    if (self) {
        if (keyData == nil) {
            return nil;
        }
        
        SecCertificateRef certificate;
        SecPolicyRef policy;
        SecTrustRef trust;

        certificate = SecCertificateCreateWithData(kCFAllocatorDefault, ( __bridge CFDataRef) keyData);
        if (certificate == nil) {
            NSLog(@"Can not read certificate from data");
            return nil;
        }

        policy = SecPolicyCreateBasicX509();
        OSStatus returnCode = SecTrustCreateWithCertificates(certificate, policy, &trust);
        if (returnCode != noErr) {
            NSLog(@"SecTrustCreateWithCertificates fail. Error Code: %d", (int)returnCode);
            CFRelease(certificate);
            CFRelease(policy);
            return nil;
        }

        // TODO: Sigh, Apple doesn't make this fool-proof:
        /* Because this function might look on the network for certificates in the certificate chain, the function might block while attempting network access. You should never call it from your main thread; call it only from within a function running on a dispatch queue or on a separate thread. Alternatively, in macOS, you can use SecTrustEvaluateAsync from your main thread. In iOS, you can do the same thing using dispatch_once.
         
            So we should probably dispatch this on another thread in the future. And all we're trying to get is get a public key from a *.der file...
         */

        SecTrustResultType trustResultType;
        returnCode = SecTrustEvaluate(trust, &trustResultType);
        if (returnCode != noErr) {
            NSLog(@"SecTrustEvaluate fail. Error Code: %d", (int)returnCode);
            CFRelease(certificate);
            CFRelease(policy);
            CFRelease(trust);
            return nil;
        }
 
        // The trustResultType seems to always be: kSecTrustResultRecoverableTrustFailure, but we don't care.
        // We are just looking for the public key, below.
        
        _publicKey = SecTrustCopyPublicKey(trust);
        if (_publicKey == nil) {
            NSLog(@"SecTrustCopyPublicKey fail");
            CFRelease(certificate);
            CFRelease(policy);
            CFRelease(trust);
            return nil;
        }

        NSInteger keyLength = SecKeyGetBlockSize(_publicKey);
        self.keyLength = @(keyLength);
        _maxPlainLen = keyLength - 12;
        
        CFRelease(certificate);
        CFRelease(policy);
        CFRelease(trust);
    }

    return self;
}


- (NSData *) encryptWithData:(NSData *)content {
    size_t plainLen = [content length];
    if (plainLen > self.maxPlainLen) {
        NSLog(@"content(%ld) is too long, must < %ld", plainLen, self.maxPlainLen);
        return nil;
    }

    size_t cipherLen = [self.keyLength integerValue];
    void *cipher = malloc(cipherLen);

    // TODO - possible optimization with NSMutableData:
    // "The input buffer (plainText) can be the same as the output buffer (cipherText) to reduce the amount of memory used by the function." - Apple Docs
    OSStatus returnCode = SecKeyEncrypt(self.publicKey, kSecPaddingPKCS1, [content bytes],
                                        plainLen, cipher, &cipherLen);

    NSData *result = nil;
    if (returnCode != noErr) {
        NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)returnCode);
        free(cipher);
    }
    else {
        result = [NSData dataWithBytesNoCopy:cipher length:cipherLen];
    }

    return result;
}


- (void)dealloc
{
    CFRelease(_publicKey);
}

@end
