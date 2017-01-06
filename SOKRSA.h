#import <Foundation/Foundation.h>

@interface SOKRSA : NSObject

@property (nonatomic) size_t maxPlainLen;

- (instancetype _Nullable)initWithDERData:(NSData * _Nonnull)keyData;

// Encrypt with a public key. Data will only be decryptable with the corresponsing private key.
- (NSData * _Nullable) encryptWithData:(NSData * _Nonnull)content;

// Decryption can be done with openssl, but we didn't find a way to do it so far with
//  CommonCrypto library build into iOS.


@end
