//
//  SSLManager.h
//  privateChat
//
//  Created by chenchuanbo on 15/3/2.
//  Copyright (c) 2015年 wanggang. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface CCBOSSLManager : NSObject

+ (instancetype)shareInstance;
- (void)sendMessage:(const char *)message withLength:(int)msglength withUrl:(NSString *)url withPort:(int)port;

@end
