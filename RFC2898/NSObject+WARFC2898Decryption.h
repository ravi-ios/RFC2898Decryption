//
//  NSObject+WARFC2898Decryption.h
//  WARFC2898
//
//  Created by Ravi on 11/09/15.
//  Copyright (c) 2015 Ravi. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSObject (WARFC2898Decryption)

-(BOOL)verifyHashPassword:(NSString *)hashPassword withPassword:(NSString *)password;

@end
