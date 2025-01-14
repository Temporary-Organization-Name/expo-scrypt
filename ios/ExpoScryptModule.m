#import <ExpoModulesCore/ExpoModulesCore.h>
#import <CommonCrypto/CommonCrypto.h>

@interface ExpoScryptModule : ExpoModule
@end

@implementation ExpoScryptModule

EX_EXPORT_MODULE(ExpoScrypt);

EX_EXPORT_METHOD_AS(scrypt,
                    scrypt:(NSString *)password
                    withSalt:(NSString *)salt
                    withOptions:(NSDictionary *)options
                    resolver:(EXPromiseResolveBlock)resolve
                    rejecter:(EXPromiseRejectBlock)reject)
{
    // Check for null parameters
    if (!password || !salt || !options) {
        reject(@"ERR_INVALID_PARAMS", @"Password, salt, and options must not be null", nil);
        return;
    }
    
    NSNumber *N = options[@"N"];
    NSNumber *r = options[@"r"];
    NSNumber *p = options[@"p"];
    NSNumber *dkLen = options[@"dkLen"];
    
    // Check if all required options are present
    if (!N || !r || !p || !dkLen) {
        reject(@"ERR_INVALID_PARAMS", @"N, r, p, and dkLen must be provided", nil);
        return;
    }
    
    // Validate N is a power of 2
    uint64_t nValue = N.unsignedLongLongValue;
    if (nValue == 0 || (nValue & (nValue - 1)) != 0) {
        reject(@"ERR_INVALID_PARAMS", @"N must be a power of 2", nil);
        return;
    }
    
    // Validate reasonable bounds
    if (nValue < 2 || nValue > 16777216) { // Max N = 2^24
        reject(@"ERR_INVALID_PARAMS", @"N must be between 2 and 16777216", nil);
        return;
    }
    
    uint32_t rValue = r.unsignedIntValue;
    uint32_t pValue = p.unsignedIntValue;
    uint32_t dkLenValue = dkLen.unsignedIntValue;
    
    if (rValue == 0 || rValue > 256) {
        reject(@"ERR_INVALID_PARAMS", @"r must be between 1 and 256", nil);
        return;
    }
    
    if (pValue == 0 || pValue > 256) {
        reject(@"ERR_INVALID_PARAMS", @"p must be between 1 and 256", nil);
        return;
    }
    
    if (dkLenValue == 0 || dkLenValue > 64) {
        reject(@"ERR_INVALID_PARAMS", @"dkLen must be between 1 and 64", nil);
        return;
    }
    
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    NSData *saltData = [salt dataUsingEncoding:NSUTF8StringEncoding];
    
    // Validate password and salt lengths
    if (passwordData.length == 0 || passwordData.length > 1024) {
        reject(@"ERR_INVALID_PARAMS", @"Password length must be between 1 and 1024 bytes", nil);
        return;
    }
    
    if (saltData.length < 8 || saltData.length > 32) {
        reject(@"ERR_INVALID_PARAMS", @"Salt length must be between 8 and 32 bytes", nil);
        return;
    }
    
    // Check if r * p doesn't exceed 2^30
    if ((uint64_t)rValue * (uint64_t)pValue >= (1ULL << 30)) {
        reject(@"ERR_INVALID_PARAMS", @"r * p must be less than 2^30", nil);
        return;
    }
    
    uint8_t *derivedKey = malloc(dkLenValue);
    if (derivedKey == NULL) {
        reject(@"ERR_MEMORY", @"Failed to allocate memory", nil);
        return;
    }
    
    int result = CCCryptoScrypt(
        passwordData.bytes,
        passwordData.length,
        saltData.bytes,
        saltData.length,
        nValue,
        rValue,
        pValue,
        derivedKey,
        dkLenValue
    );
    
    if (result != 0) {
        free(derivedKey);
        reject(@"ERR_SCRYPT_FAILED", @"Scrypt operation failed", nil);
        return;
    }
    
    NSData *derivedKeyData = [NSData dataWithBytes:derivedKey length:dkLenValue];
    free(derivedKey);
    
    NSString *hexString = [self hexStringFromData:derivedKeyData];
    resolve(hexString);
}

- (NSString *)hexStringFromData:(NSData *)data {
    const unsigned char *dataBuffer = (const unsigned char *)[data bytes];
    NSUInteger dataLength = [data length];
    NSMutableString *hexString = [NSMutableString stringWithCapacity:(dataLength * 2)];
    
    for (int i = 0; i < dataLength; ++i) {
        [hexString appendFormat:@"%02x", dataBuffer[i]];
    }
    
    return [hexString copy];
}

@end 