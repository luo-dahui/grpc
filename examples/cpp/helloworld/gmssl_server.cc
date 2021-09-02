#include <iostream>
#include <memory>
#include <string>

#include <grpc++/grpc++.h>
#include <grpc++/security/credentials.h>
#include <fstream>

#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "helloworld.grpc.pb.h"
#endif

#include <openssl/bio.h>
#include <openssl/crypto.h> /* For OPENSSL_free */
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using helloworld::HelloRequest;
using helloworld::HelloReply;
using helloworld::Greeter;
using namespace std;

bool verify_enc(SSL_CTX* ctx, const string& enc_cert, const string& enc_key)
{
  cout << "verify_enc1111" << endl;
  // enc cert
  if (SSL_CTX_use_enc_certificate_file(ctx, enc_cert.c_str(), SSL_FILETYPE_PEM) <= 0) {
    cout << "Init, SSL_CTX_use_enc_certificate_file failed." << endl;
    return false;
  }
  cout << "verify_enc222" << endl;
  // enc private key
  if (SSL_CTX_use_enc_PrivateKey_file(ctx, enc_key.c_str(), SSL_FILETYPE_PEM) <= 0) {
    cout << "Init, SSL_CTX_use_enc_PrivateKey_file failed." << endl;
    return false;
  }
  cout << "verify_enc333" << endl;
  // check enc private key is ok
  if (!SSL_CTX_check_enc_private_key(ctx)) {
    cout << "Init, SSL_CTX_check_enc_private_key failed." << endl;
    return false;
  }
  cout << "verify_enc succeed!" << endl;
  return true;
}

bool verify_sign(SSL_CTX* ctx, const string& sign_cert, const string& sign_key)
{
  cout << "test_gmssl6666, sersign_certvercert:" << sign_cert << endl;
  // sign cert
  if (SSL_CTX_use_certificate_file(ctx, sign_cert.c_str(), SSL_FILETYPE_PEM) <= 0) {
    cout << "Init, SSL_CTX_use_certificate_file failed." << endl;
    return false;
  }
  cout << "test_gmssl777" << endl;
  // sign private key
  if (SSL_CTX_use_PrivateKey_file(ctx, sign_key.c_str(), SSL_FILETYPE_PEM) <= 0) {
    cout << "Init, SSL_CTX_use_PrivateKey_file failed." << endl;
    return false;
  }

  // check sign private key is ok
  if (!SSL_CTX_check_private_key(ctx)) {
    cout << "Init, SSL_CTX_check_private_key failed." << endl;
    return false;
  }
  return true;
}

bool init_gmssl()
{
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  return true;
}

bool verify_root(SSL_CTX* ctx, const string& root_crt)
{
  cout << "start verify root" << endl;
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

  string pass = "123456";
  SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)pass.c_str());
  if (SSL_CTX_load_verify_locations(ctx, root_crt.c_str(), NULL) <= 0) 
  {
    cout << "Init, SSL_CTX_load_verify_locations failed." << endl;
    return false;
  }
  cout << "verify root succeed!" << endl;
  return true;
}

static std::string get_file_contents(const char *fpath)
{
  std::ifstream finstream(fpath);
  std::string contents;
  contents.assign((std::istreambuf_iterator<char>(finstream)),
                       std::istreambuf_iterator<char>());
  finstream.close();
  return contents;
}

// Logic and data behind the server's behavior.
class GreeterServiceImpl final : public Greeter::Service {
  Status SayHello(ServerContext* context, const HelloRequest* request,
                  HelloReply* reply) override {

    cout << "get request:" << request->name() << endl;
    std::string prefix("GMSSL Server Respon: Hello ");
    reply->set_message(prefix + request->name());
    return Status::OK;
  }
};

void RunServer(char** argv) {
  gpr_set_log_verbosity(GPR_LOG_SEVERITY_INFO);

  // std::string server_address("localhost:50051");
  // std::string server_address("192.168.2.128:50051");
  std::string server_address("0.0.0.0:50051");
  // std::string server_address("127.0.0.1:50051");
  
  GreeterServiceImpl service;

  string root_crt = argv[1]; // for verifying clients
  // 签名证书
  string serverkey  = argv[2];
  string servercert = argv[3];
  // 加密证书
  string enc_key  = argv[4];
  string enc_cert = argv[5];

  grpc::SslServerCredentialsOptions::PemKeyCertPair sig_pkcp = {
    serverkey.c_str(), servercert.c_str()
  };

  grpc::SslServerCredentialsOptions::PemKeyCertPair enc_pkcp = {
    enc_key.c_str(), enc_cert.c_str()
  };

  // grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
  grpc::SslServerCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs = root_crt;
  ssl_opts.pem_key_cert_pairs.push_back(sig_pkcp);
  ssl_opts.pem_key_cert_pairs.push_back(enc_pkcp);
  std::shared_ptr<grpc::ServerCredentials> creds;
  creds = grpc::SslServerCredentials(ssl_opts);

  ServerBuilder builder;
  builder.AddListeningPort(server_address, creds);
  builder.RegisterService(&service);
  std::unique_ptr<Server> server(builder.BuildAndStart());

  gpr_log(GPR_INFO, "Server listening on %s.", server_address.c_str());

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

int test_gmssl(char** argv) {
  SSL_CTX** ctx;
  string root_crt = argv[1];
  // 加密证书
  string enc_key  = argv[2];
  string enc_cert = argv[3];
  // 签名证书
  string sign_key  = argv[4];
  string sign_cert = argv[5];

  init_gmssl();
  *ctx = SSL_CTX_new(SSLv23_server_method());
  if (ctx == NULL) 
  {
    cout << "Init, SSL_CTX_new failed." << endl;
    return -1;
  }

  cout << "start verify root" << endl;
  if (!(SSL_CTX_set_mode(*ctx, SSL_MODE_AUTO_RETRY) & SSL_MODE_AUTO_RETRY)) {
    ERR_print_errors_fp(stdout);
    cout << "Init, SSL_CTX_set_mode failed." << endl;
    return false;
  }
  SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

  string pass = "123456";
  SSL_CTX_set_default_passwd_cb_userdata(*ctx, (void*)pass.c_str());

  // sign
  if(!verify_sign(*ctx, sign_cert, sign_key))
  {
    return -1;
  }

  // enc
  if(!verify_enc(*ctx, enc_cert, enc_key))
  {
    return -1;
  }

  if (SSL_CTX_load_verify_locations(*ctx, root_crt.c_str(), NULL) <= 0) 
  {
    cout << "Init, SSL_CTX_load_verify_locations failed." << endl;
    return false;
  }
  cout << "verify root succeed!" << endl;

  SSL_CTX_set_verify_depth(*ctx, 10);

  cout << "init succeed====" << endl;
  return 0;
}


int main(int argc, char** argv) {
  RunServer(argv);
  // test_gmssl(argv);
  return 0;
}