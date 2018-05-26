//
//  NSObject+WARFC2898Decryption.m
//  WARFC2898
//
//  Created by Ravi on 11/09/15.
//  Copyright (c) 2015 Ravi. All rights reserved.
//

#import "NSObject+WARFC2898Decryption.h"

#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonHMAC.h>

#define BLOCK_SIZE_16 0x10
#define BLOCK_SIZE_32 0x20
#define BLOCK_SIZE_49 0x31

@implementation NSObject (WARFC2898Decryption)

- (BOOL)verifyHashPassword:(NSString *)hashPassword withPassword:(NSString *)password ß{
    if(hashPassword.length == 0 && password.length == 0) {
        return  YES;
    }
    if(hashPassword.length == 0) {
        return NO;
    }
    if(password.length == 0) {
        return NO;
    }
    NSData *hashPasswordData= [[NSData alloc] initWithBase64EncodedString:hashPassword options:NSASCIIStringEncoding];
    unsigned char *hashPasswordByteData = (unsigned char *)[hashPasswordData bytes];
    int firstByte = hashPasswordByteData[0];
    /* First byte should be 0 and total buffer size should be 49 bytes  */
    if (hashPasswordData.length != 49 || firstByte!=0) {
        return false;
    }
    
    /* salt should be of size 16 byte */
    NSMutableData *saltData = [NSMutableData dataWithLength:BLOCK_SIZE_16];
    saltData = [[hashPasswordData subdataWithRange:NSMakeRange(1, BLOCK_SIZE_16)] copy];
    
    /* Password key should be 32 byte */
    NSMutableData *hashPasswordKey = [NSMutableData dataWithLength:BLOCK_SIZE_32];
    hashPasswordKey = [[hashPasswordData subdataWithRange:NSMakeRange(0x11, BLOCK_SIZE_32)] copy];
    
    /* total buffer size should be 49 bytes  */
    NSMutableData *derivedData = [NSMutableData dataWithLength:BLOCK_SIZE_49];
    
    [self deriveBytes:derivedData fromPassword:password andSalt:saltData withIterations:1000];
    /* Password key should be 32 byte */
    NSMutableData *userPasswordKey = [NSMutableData dataWithLength:BLOCK_SIZE_32];
    userPasswordKey = [[derivedData subdataWithRange:NSMakeRange(0x0, BLOCK_SIZE_32)] copy];
    
    /* Compare user password key and hash password key should if both are then enterd passcode will be right */
    if ([userPasswordKey isEqualToData:hashPasswordKey]) {
        NSLog(@"Authentication success");
        return YES;
    }else{
        NSLog(@"Authentication failure");
        return NO;
    }
}


- (void)deriveBytes:(NSMutableData *)deriveBytes fromPassword:(NSString *)password andSalt:(NSData *)salt withIterations:(const int)iterations {
    
    //
    //  We work with the password as a UTF8 encoded byte stream.
    //
    
    const char *passPhraseBytes = [password UTF8String];
    NSInteger passPhraseLength = strlen(passPhraseBytes);
    
    //
    //  Copy the salt into a mutable buffer. We need to append 4 bytes
    //  onto the end that we change through each iteration of the algorithm.
    //
    
    NSMutableData *mSalt = [NSMutableData dataWithData:salt];
    [mSalt increaseLengthBy:4];
    
    //
    //  Other buffers & counters used for executing RFC2898.
    //
    
    unsigned char mac[CC_SHA1_DIGEST_LENGTH];
    unsigned char outputBytes[CC_SHA1_DIGEST_LENGTH];
    unsigned char U[CC_SHA1_DIGEST_LENGTH];
//    const int iterations = kIterations;//1000
    int i=1;
    int generatedBytes = 0;
    unsigned char blockCount = 0;
    
    while (generatedBytes < [deriveBytes length]) {
        bzero(mac, CC_SHA1_DIGEST_LENGTH);
        bzero(outputBytes, CC_SHA1_DIGEST_LENGTH);
        bzero(U, CC_SHA1_DIGEST_LENGTH);
        
        //
        //  Each time through this loop, I need to update the very last byte
        //  of the salt buffer. (If I implemented the full RFC2898 algorithm,
        //  then I'd be ready to twiddle the last 4 bytes. I don't.)
        //
        
        blockCount++;
        unsigned char *mSaltBytes = (unsigned char *)[mSalt mutableBytes];
        mSaltBytes[[mSalt length]-1] = blockCount;
        
        memcpy(U, [mSalt bytes], [mSalt length]);
        
        //
        //  First iteration. I have to split these apart because the data length
        //  is different between the first iteration (12 bytes) and each subsequent
        //  iteration (20 bytes).
        //
        
        CCHmac(kCCHmacAlgSHA1, passPhraseBytes, passPhraseLength, [mSalt bytes], [mSalt length], mac);
        for (i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
            outputBytes[i] ^= mac[i];
            U[i] = mac[i];
            
        }
        
        //
        //  All subsequent iterations.
        //
        
        for (int iteration = 1; iteration < iterations; iteration++) {
            CCHmac(kCCHmacAlgSHA1, passPhraseBytes, passPhraseLength, U, CC_SHA1_DIGEST_LENGTH, mac);
            for (i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
                outputBytes[i] ^= mac[i];
                U[i] = mac[i];
            }
        }
        
        NSInteger bytesNeeded = [deriveBytes length] - generatedBytes;
        NSInteger bytesToCopy = MIN(bytesNeeded, CC_SHA1_DIGEST_LENGTH);
        [deriveBytes replaceBytesInRange:NSMakeRange(generatedBytes, bytesToCopy) withBytes:outputBytes];
        generatedBytes += bytesToCopy;
    }
}

@end
