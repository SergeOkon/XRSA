#import <Foundation/Foundation.h>

@interface XRSA : NSObject

@property (nonatomic) size_t maxPlainLen;

- (XRSA *)initWithDERData:(NSData *)keyData;
- (NSData *) encryptWithData:(NSData *)content;

@end
