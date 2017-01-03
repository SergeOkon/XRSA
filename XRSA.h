#import <Foundation/Foundation.h>

@interface XRSA : NSObject

@property (nonatomic) size_t maxPlainLen;

- (XRSA *)initWithData:(NSData *)keyData;
- (XRSA *)initWithPublicKey:(NSString *)publicKeyPath;

- (NSData *) encryptWithData:(NSData *)content;

@end
