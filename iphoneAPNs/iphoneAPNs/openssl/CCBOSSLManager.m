//
//  SSLManager.m
//  privateChat
//
//  Created by chenchuanbo on 15/3/2.
//  Copyright (c) 2015年 wanggang. All rights reserved.
//

#import "CCBOSSLManager.h"
#import <openssl/ssl.h>
#import <OpenSsl/x509.h>
#import <Openssl/x509v3.h>
#import <openssl/pkcs12.h>
#import <openssl/err.h>

#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <netdb.h>

@interface CCBOSSLManager()
{
    SSL_CTX *_ctx;
    SSL *_ssl;
    int _sock;
}
@property (strong, nonatomic) NSOperationQueue *sendMsgQueue;
@end

@implementation CCBOSSLManager

static id sharedInstance = nil;
+ (instancetype)shareInstance
{
    static dispatch_once_t predicate;
    dispatch_once(&predicate, ^{
        sharedInstance = [[self alloc] init];
    });
    return sharedInstance;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.sendMsgQueue = [[NSOperationQueue alloc] init];
        [self.sendMsgQueue setMaxConcurrentOperationCount:1];;
        _sock = -1;
        //
        NSBlockOperation *operation = [NSBlockOperation blockOperationWithBlock:^{
            [self sslInitWithCert];
            NSString *certFilePath = [[NSBundle mainBundle] pathForResource:@"rootCert" ofType:@"pem"];
            NSString *userFilePath = [[NSBundle mainBundle] pathForResource:@"userCert" ofType:@"pem"];
            NSString *userkeyFilePath = [[NSBundle mainBundle] pathForResource:@"userCert" ofType:@"pem"];
            [self sslInitContext:userFilePath withCertKey:userkeyFilePath withCertKeyPassword:@"" withCert:certFilePath];
        }];
        [self.sendMsgQueue addOperation:operation];
    }
    return self;
}

- (void)dealloc
{
    if (_ctx) {
        SSL_CTX_free (_ctx);
        _ctx = nil;
    }
}

- (void)connectServer:(NSString *)host withPort:(NSInteger)port
{
    if (_sock != -1) {
        close(_sock);
    }
    if (_ssl) {
        SSL_shutdown(_ssl);
        SSL_free (_ssl);
        _ssl = nil;
    }
    _sock = tcp_connect([host cStringUsingEncoding:NSUTF8StringEncoding], (int)port);
    if (_sock != -1) {
        if (_ctx) {
            _ssl = ssl_connect(_ctx, _sock);
            if (_ssl) {
                if ([self verify_connection:_ssl withPeerName:host] < 0) {
                    SSL_shutdown(_ssl);
                    SSL_free (_ssl);
                    _ssl = nil;
                }
            }
        }
    }
}

int np_socket_alive(int sock)
{
    char buff[32];
    int recv_buff = recv(sock, buff, sizeof (buff), MSG_PEEK);
    int sockErr = errno;
    if (recv_buff > 0)  // Get Data
        return 1;
    if ((recv_buff == -1) && (sockErr == EWOULDBLOCK))
        return 1;
    return -1;
}

- (void)sendMessage:(const char *)message withLength:(int)msglength withUrl:(NSString *)url withPort:(int)port
{
    if (!_ssl || np_socket_alive(_sock) == -1) {
        [self connectServer:url withPort:port];
    }
    if (_ssl) {
        int nwrite = SSL_write(_ssl, message, msglength);
        if (nwrite < 0) {
            ERR_print_errors_fp(stderr);
        }
    }
}

#pragma mark ssl context
// 初始化SSL库
- (void)sslInitWithCert
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

- (BOOL)sslInitContext:(NSString *)clientcert withCertKey:(NSString *)clientkey withCertKeyPassword:(NSString *)keypwd withCert:(NSString *)cert
{
    // 初始化ssl context
    _ctx = SSL_CTX_new(SSLv23_client_method());
    /*
     *加载信任证书（连接时，会从服务端下载相关信息和本地信任证书比较，如果在信任证书范围内则连接。ssl协议中客户端一般要验证服务端证书，而服务端一般不要求验证客户端证书，但特殊情况下服务端也可以要求客户端发送证书）
     */
    // 是否要验证证书
    SSL_CTX_set_verify(_ctx,SSL_VERIFY_PEER, 0);
    if (!SSL_CTX_load_verify_locations(_ctx, [cert cStringUsingEncoding:NSUTF8StringEncoding], 0)) {
        SSL_CTX_free (_ctx);
        _ctx = nil;
        return NO;
    }
    /*
     *加载用户证书（使用用户证书加密传输信息）
     */
    // 加载证书密码
    if (keypwd.length > 0) {
        SSL_CTX_set_default_passwd_cb_userdata(_ctx, (void *)[keypwd cStringUsingEncoding:NSUTF8StringEncoding]);
    }
    // 加载用户证书
    if (SSL_CTX_use_certificate_file(_ctx, [clientcert cStringUsingEncoding:NSUTF8StringEncoding], SSL_FILETYPE_PEM) < 0) {
        SSL_CTX_free (_ctx);
        _ctx = nil;
        return NO;
    }
    // 加载用户私钥
    if (SSL_CTX_use_PrivateKey_file(_ctx, [clientkey cStringUsingEncoding:NSUTF8StringEncoding], SSL_FILETYPE_PEM) < 0) {
        SSL_CTX_free (_ctx);
        _ctx = nil;
        return NO;
    }
    // 检查私钥与用户证书是否一致
    if (SSL_CTX_check_private_key(_ctx) < 0) {
        SSL_CTX_free (_ctx);
        _ctx = nil;
        return NO;
    }
    // 设置客户端能支持的加密方式，按照ssl协议，这个要提交到服务端
    //SSL_CTX_set_cipher_list(_ctx,"RC4-MD5");
    return YES;
}

#pragma mark connect ssl
// 建立tcp连接
int tcp_connect(const char* host, int port)
{
    struct hostent *hp;
    struct sockaddr_in addr;
    int sock = -1;
    // 解析域名
    if (!(hp = gethostbyname(host))) {
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_addr = *(struct in_addr*)hp->h_addr_list[0];
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
        return -1;
    }
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }
    return sock;
}

// 建立ssl连接
SSL* ssl_connect(SSL_CTX* ctx, int socket)
{
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        close(socket);
        return nil;
    }
    SSL_set_fd (ssl, socket);
    int err = SSL_connect(ssl);
    if (err <= 0) {
        close(socket);
        SSL_shutdown(ssl);
        ERR_print_errors_fp(stderr);
        return nil;
    }
    return ssl;
}

// 检验证书是否有效
- (int)verify_connection:(SSL*)ssl withPeerName:(NSString *)peername
{
    long result = SSL_get_verify_result(ssl);
    if (result != X509_V_OK) {
        fprintf(stderr, "WARNING! ssl verify failed: %ld", result);
        return -1;
    }
    X509 *peer;
    char peer_CN[256] = {0};
    peer = SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 255);
    if (strcmp(peer_CN, [peername cStringUsingEncoding:NSUTF8StringEncoding]) != 0) {
        fprintf(stderr, "WARNING! Server Name Doesn't match, got: %s, required: %s", peer_CN,
                [peername cStringUsingEncoding:NSUTF8StringEncoding]);
    }
    return 0;
}

#pragma mark parser local file
- (void)loadP12:(NSString *)p12Path withPassword:(NSString *)passwd
{
    X509 *_client_cert = nil;
    PKCS12 *p12 = nil;
    EVP_PKEY* pkey = nil;
    STACK_OF(X509)* ca = nil;
    SSLeay_add_all_algorithms();
    BIO *bio = BIO_new_file([p12Path cStringUsingEncoding:NSUTF8StringEncoding], "r");
    //parser P12
    p12 = d2i_PKCS12_bio(bio, nil); //得到p12结构
    BIO_free_all(bio);
    PKCS12_parse(p12, [passwd cStringUsingEncoding:NSUTF8StringEncoding], &pkey, &_client_cert, &ca); //得到x509结构
    PKCS12_free(p12);
    EVP_PKEY_free(pkey);
    sk_X509_free(ca);
    X509_free(_client_cert);
}

- (void)parserCertification:(X509 *)cert
{
    char* p = nil;
    if (cert)
    {
        fprintf(stdout, "***User Certificate***\n");
        fprintf(stdout, "Subject:");
        p = X509_NAME_oneline(X509_get_subject_name(cert), nil, 0);
        fprintf(stdout, "%s\n", p);
        //
        fprintf(stdout, "Issuer:");
        p = X509_NAME_oneline(X509_get_issuer_name(cert), nil, 0);
        fprintf(stdout, "%s\n", p);
        //
        fprintf(stdout, "public key:");
        EVP_PKEY *pKey = X509_get_pubkey(cert);
        unsigned char buffer[2048] = {0};
        unsigned char *key = buffer;
        int len = 0;
        len = i2d_PUBKEY(pKey, &key);
        printf("the public key length is %d\n", len);
        for (int i = 0; i < len; i++)
        {
            if(0 == i%16)
            {
                printf("\n");
            }
            printf("  %02x", buffer[i]);
        }
    }
}
@end
