//
//  GuestSid.m
//  Pyramid
//
//  Created by chens on 15/10/9.
//  Copyright © 2015年 QMX. All rights reserved.
//

#import "GuestSid.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>


@implementation GuestSid

+ (NSString*)getSid{
    NSTimeInterval time = [[NSDate date] timeIntervalSince1970];

    unsigned int day=(unsigned int) time/(24*3600);

    Byte aByte[12];
    
    int i = rand()%100000000;
    
    long x = (long)(time * 10000000 + i) | LONG_MIN;
    for (int i=0; i<12; i++) {
        if (i<4) {
            aByte[i]=(Byte)(day>>(3-i)*8)&0xFF;
        }else{
            aByte[i]=(Byte)(x>> (11-i)*8)&0xFF;
        }
    }
    
    NSData *data = [NSData dataWithBytes:aByte length:12];

    NSData *sid = [GuestSid encrypt:data withKey:@"%)#(*N@CHGPX><ABMvMghsO*"];
    
    NSLog(@"sid = %@" , [GuestSid hexStringFromString:sid]);
    
    return [GuestSid hexStringFromString:sid].uppercaseString;
}

+ (NSData *)encrypt:(NSData *)sourceData withKey:(NSString*)key
{
    
    size_t dataBufferSize = [sourceData length];
    const void *sourceBytes = (const void *)[sourceData bytes];
    
    size_t movedBytes = 0;
    
    size_t bufferPtrSize = (dataBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    uint8_t *bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    
    const void *vkey = (const void *)[key UTF8String];
    
    CCCrypt(kCCEncrypt,
            kCCAlgorithm3DES,
            kCCOptionPKCS7Padding | kCCOptionECBMode,
            vkey,
            kCCKeySize3DES,
            nil,
            sourceBytes,
            dataBufferSize,
            (void *)bufferPtr,
            bufferPtrSize,
            &movedBytes);
    
    NSData *result = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes];
    free(bufferPtr);

    return result;
}
+ (NSString *)hexStringFromString:(NSData *)myD{
    Byte *bytes = (Byte *)[myD bytes];
    //下面是Byte 转换为16进制。
    NSString *hexStr=@"";
    for(int i=0;i<[myD length];i++)
        
    {
        NSString *newHexStr = [NSString stringWithFormat:@"%x",bytes[i]&0xff];///16进制数
        
        if([newHexStr length]==1)
            
            hexStr = [NSString stringWithFormat:@"%@0%@",hexStr,newHexStr];
        
        else
            
            hexStr = [NSString stringWithFormat:@"%@%@",hexStr,newHexStr]; 
    } 
    return hexStr; 
}

@end
