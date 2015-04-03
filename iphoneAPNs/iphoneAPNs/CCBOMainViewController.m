//
//  CCBOMainViewController.m
//  iphoneAPNs
//
//  Created by chenchuanbo on 15/4/3.
//  Copyright (c) 2015年 ccbo. All rights reserved.
//

#import "CCBOMainViewController.h"
#import "CCBOSSLManager.h"

#define APNsurl @"gateway.push.apple.com"
#define SANDBOXAPNsurl  @"gateway.sandbox.push.apple.com"
#define APNsport  2195
#define DEVICE_BINARY_SIZE  32
#define MAXPAYLOAD_SIZE 255

@interface CCBOMainViewController ()

@property (strong, nonatomic) UITextField *tokenTextField;
@property (strong, nonatomic) UITextField *contentTextField;
@property (assign, nonatomic) NSInteger pushId;

@end

@implementation CCBOMainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor whiteColor];
    //
    UILabel *tokenLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    tokenLabel.text = @"token";
    tokenLabel.backgroundColor = [UIColor clearColor];
    [tokenLabel setTranslatesAutoresizingMaskIntoConstraints:NO];
    [self.view addSubview:tokenLabel];
    //
    self.tokenTextField = [[UITextField alloc] initWithFrame:CGRectZero];
    [self.tokenTextField setTranslatesAutoresizingMaskIntoConstraints:NO];
    self.tokenTextField.placeholder = @"input iphone token";
    self.tokenTextField.borderStyle = UITextBorderStyleRoundedRect;
    [self.view addSubview:self.tokenTextField];
    //
    UILabel *contentLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    contentLabel.text = @"content";
    contentLabel.backgroundColor = [UIColor clearColor];
    [contentLabel setTranslatesAutoresizingMaskIntoConstraints:NO];
    [self.view addSubview:contentLabel];
    //
    self.contentTextField = [[UITextField alloc] initWithFrame:CGRectZero];
    self.contentTextField.placeholder = @"input content";
    self.contentTextField.borderStyle = UITextBorderStyleRoundedRect;
    [self.contentTextField setTranslatesAutoresizingMaskIntoConstraints:NO];
    [self.view addSubview:self.contentTextField];
    //
    UIButton *sendButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [sendButton addTarget:self action:@selector(sendMessage:) forControlEvents:UIControlEventTouchUpInside];
    [sendButton setTranslatesAutoresizingMaskIntoConstraints:NO];
    [sendButton setTitle:@"send" forState:UIControlStateNormal];
    [sendButton setTitle:@"send" forState:UIControlStateHighlighted];
    [sendButton setBackgroundColor:[UIColor greenColor]];
    [self.view addSubview:sendButton];
    //
    NSMutableArray *contentConstraints = [NSMutableArray array];
    [contentConstraints addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:@"H:|-20-[tokenLabel(==70)][tokenTextField]-20-|" options:0 metrics:nil views:@{@"tokenLabel":tokenLabel, @"tokenTextField":self.tokenTextField}]];
    [contentConstraints addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:@"H:|-20-[contentLabel(==70)][contentTextField]-20-|" options:0 metrics:nil views:@{@"contentLabel":contentLabel, @"contentTextField":self.contentTextField}]];
    [contentConstraints addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:@"H:|-20-[sendButton]-20-|" options:0 metrics:nil views:@{@"sendButton":sendButton}]];
    [contentConstraints addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:@"V:|-100-[tokenLabel(==40)]-20-[contentLabel(==40)]-20-[sendButton(==40)]" options:0 metrics:nil views:@{@"tokenLabel":tokenLabel, @"contentLabel":contentLabel, @"sendButton":sendButton}]];
    [contentConstraints addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:@"V:|-100-[tokenTextField(==40)]-20-[contentTextField(==40)]" options:0 metrics:nil views:@{@"tokenTextField":self.tokenTextField, @"contentTextField":self.contentTextField}]];
    
    [self.view addConstraints:contentConstraints];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)sendMessage:(id)sender
{
    NSString *userFilePath = [[NSBundle mainBundle] pathForResource:@"userCert" ofType:@"pem"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:userFilePath]) {
        UIAlertView *alter = [[UIAlertView alloc]initWithTitle:@"提示" message:@"请把你的证书（命名为userCert.pem）加入到工程中，重新编译" delegate:nil cancelButtonTitle:@"Cancel" otherButtonTitles:nil, nil];
        [alter show];
        return;
    }
    NSData *token = [self stringToTokenData:self.tokenTextField.text];
    if (!token) {
        UIAlertView *alter = [[UIAlertView alloc]initWithTitle:@"Error" message:@"wrong token" delegate:nil cancelButtonTitle:@"Cancel" otherButtonTitles:nil, nil];
        [alter show];
        return;
    }
    NSString *content = self.contentTextField.text;
    if (!content || content.length == 0) {
        UIAlertView *alter = [[UIAlertView alloc]initWithTitle:@"Error" message:@"content is not empty" delegate:nil cancelButtonTitle:@"Cancel" otherButtonTitles:nil, nil];
        [alter show];
        return;
    }
    if (content.length > 200) {
        UIAlertView *alter = [[UIAlertView alloc]initWithTitle:@"Error" message:@"content is too long" delegate:nil cancelButtonTitle:@"Cancel" otherButtonTitles:nil, nil];
        [alter show];
        return;
    }
    NSData *jsonData = [self componetMessage:content withBubble:1 withSound:@"default" withExtend:nil];
    [self sendPushMessageEs:jsonData toToken:token];
}

#pragma mark APNs
- (NSData *)stringToTokenData:(NSString *)tokenString
{
    if (tokenString.length != 64) {
        return nil;
    }
    char buffer[64];
    char *bufferPtr = buffer;
    for (NSInteger i = 0; i < tokenString.length; i += 2) {
        unsigned int anInt;
        NSString * hexCharStr = [tokenString substringWithRange:NSMakeRange(i, 2)];
        NSScanner * scanner = [[NSScanner alloc] initWithString:hexCharStr];
        [scanner scanHexInt:&anInt];
        *bufferPtr++ = (char)anInt;
    }
    NSData *data = [NSData dataWithBytes:buffer length:32];
    return data;
}

- (void)sendPushMessage:(NSData *)message toToken:(NSData *)token
{
    // 初始化参数
    char *deviceTokenBinary = (char *)[token bytes];
    uint16_t networkOrderTokenLength = htons(DEVICE_BINARY_SIZE);
    size_t payloadLength = message.length;
    uint16_t networkOrderPayloadLength = htons(payloadLength);
    const char *payloadBuff = [message bytes];
    uint8_t command = 0;
    // 初始化缓存
    int bufflen = sizeof(uint8_t) + sizeof(uint16_t) + DEVICE_BINARY_SIZE + sizeof(uint16_t) + MAXPAYLOAD_SIZE;
    char binaryMessageBuff[bufflen];
    memset(binaryMessageBuff, 0, bufflen);
    char *binaryMessagePt = binaryMessageBuff;
    // 填充缓存
    /* command */
    *binaryMessagePt++ = command;
    /* token length network order */
    memcpy(binaryMessagePt, &networkOrderTokenLength, sizeof(uint16_t));
    binaryMessagePt += sizeof(uint16_t);
    /* device token */
    memcpy(binaryMessagePt, deviceTokenBinary, DEVICE_BINARY_SIZE);
    binaryMessagePt += DEVICE_BINARY_SIZE;
    /* payload length network order */
    memcpy(binaryMessagePt, &networkOrderPayloadLength, sizeof(uint16_t));
    binaryMessagePt += sizeof(uint16_t);
    /* payload */
    memcpy(binaryMessagePt, payloadBuff, payloadLength);
    binaryMessagePt += payloadLength;
    // 发送数据
    [[CCBOSSLManager shareInstance] sendMessage:binaryMessageBuff withLength:(binaryMessagePt - binaryMessageBuff) withUrl:SANDBOXAPNsurl withPort:APNsport];
}

- (void)sendPushMessageEs:(NSData *)message toToken:(NSData *)token
{
    char *deviceTokenBinary = (char *)[token bytes];
    uint16_t networkOrderTokenLength = htons(DEVICE_BINARY_SIZE);
    size_t payloadLength = [message length];
    uint16_t networkOrderPayloadLength = htons(payloadLength);
    const char *payloadBuff = [message bytes];
    uint8_t command = 1;
    uint32_t whicheverOrderIWantToGetBackInAErrorResponse_ID = htonl(self.pushId++ % 1000);
    uint32_t networkOrderExpiryEpochUTC = htonl(time(NULL)+86400);
    //
    int bufflen = sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t) + DEVICE_BINARY_SIZE + sizeof(uint16_t) + MAXPAYLOAD_SIZE;
    char binaryMessageBuff[bufflen];
    memset(binaryMessageBuff, 0, bufflen);
    char *binaryMessagePt = binaryMessageBuff;
    /* command */
    *binaryMessagePt++ = command;
    /* provider preference ordered ID */
    memcpy(binaryMessagePt, &whicheverOrderIWantToGetBackInAErrorResponse_ID, sizeof(uint32_t));
    binaryMessagePt += sizeof(uint32_t);
    /* expiry date network order */
    memcpy(binaryMessagePt, &networkOrderExpiryEpochUTC, sizeof(uint32_t));
    binaryMessagePt += sizeof(uint32_t);
    /* token length network order */
    memcpy(binaryMessagePt, &networkOrderTokenLength, sizeof(uint16_t));
    binaryMessagePt += sizeof(uint16_t);
    /* device token */
    memcpy(binaryMessagePt, deviceTokenBinary, DEVICE_BINARY_SIZE);
    binaryMessagePt += DEVICE_BINARY_SIZE;
    /* payload length network order */
    memcpy(binaryMessagePt, &networkOrderPayloadLength, sizeof(uint16_t));
    binaryMessagePt += sizeof(uint16_t);
    /* payload */
    memcpy(binaryMessagePt, payloadBuff, payloadLength);
    binaryMessagePt += payloadLength;
    // 发送数据
    [[CCBOSSLManager shareInstance] sendMessage:binaryMessageBuff withLength:(binaryMessagePt - binaryMessageBuff) withUrl:SANDBOXAPNsurl withPort:APNsport];
}

- (NSData *)componetMessage:(NSString *)payload withBubble:(NSInteger)count withSound:(NSString *)soundType withExtend:(NSDictionary *)extendDict
{
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    //
    if (extendDict && extendDict.count > 0) {
        [dict addEntriesFromDictionary:extendDict];
    }
    //
    NSMutableDictionary *systemDict = [NSMutableDictionary dictionary];
    [systemDict setObject:payload forKey:@"alert"];
    [systemDict setObject:soundType forKey:@"sound"];
    [systemDict setObject:@(count) forKey:@"badge"];
    [dict setObject:systemDict forKey:@"aps"];
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dict options:NSJSONWritingPrettyPrinted error:nil];
    return jsonData;
}
@end
