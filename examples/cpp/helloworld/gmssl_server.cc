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
    std::string prefix("GMSSL Server Respon: Hello ");
    reply->set_message(prefix + request->name());
    return Status::OK;
  }
};

void RunServer(char** argv) {
  gpr_set_log_verbosity(GPR_LOG_SEVERITY_INFO);

  // std::string server_address("localhost:50051");
  std::string server_address("192.168.2.128:50051");
  // std::string server_address("0.0.0.0:50051");
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

  grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
  ssl_opts.pem_root_certs = root_crt;
  ssl_opts.pem_key_cert_pairs.push_back(sig_pkcp);
  ssl_opts.pem_key_cert_pairs.push_back(enc_pkcp);
  std::shared_ptr<grpc::ServerCredentials> creds;
  creds = grpc::SslServerCredentials(ssl_opts);

  ServerBuilder builder;
  builder.AddListeningPort(server_address, creds);
  builder.RegisterService(&service);
  std::unique_ptr<Server> server(builder.BuildAndStart());
  // std::cout << "Server listening on " << server_address << std::endl;

  gpr_log(GPR_DEBUG, "Server listening on %s.", server_address.c_str());

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

int test_gmssl(char** argv) {
  SSL_CTX** ctx;
  // auto root_crt = get_file_contents(argv[1]); // for verifying clients
  string root_crt = argv[1];
  // 签名证书
  string serverkey  = argv[2];
  string servercert = argv[3];
  // 加密证书
  string enc_key  = argv[4];
  string enc_cert = argv[5];

  cout << "test_gmssl1111" << endl;
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  cout << "test_gmssl222" << endl;
  *ctx = SSL_CTX_new(SSLv23_server_method());

  if (*ctx == NULL) {
    // ERR_print_errors_fp(stdout);
    cout << "Init, SSL_CTX_new failed." << endl;
    return -1;
  }
  cout << "test_gmssl333" << endl;

  if (!(SSL_CTX_set_mode(*ctx, SSL_MODE_AUTO_RETRY) & SSL_MODE_AUTO_RETRY)) {
    ERR_print_errors_fp(stdout);
    cout << "Init, SSL_CTX_set_mode failed." << endl;
    return -1;
  }

  cout << "test_gmssl444" << endl;

  SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

  string pass = "123456";
  SSL_CTX_set_default_passwd_cb_userdata(*ctx, (void*)pass.c_str());
  cout << "test_gmssl5555, root_crt:" << root_crt << endl;
  if (SSL_CTX_load_verify_locations(*ctx, root_crt.c_str(), NULL) <= 0) {
    cout << "Init, SSL_CTX_load_verify_locations failed." << endl;
    return -1;
  }
  
  {
    cout << "test_gmssl6666, servercert:" << servercert << endl;
    // sign cert
    if (SSL_CTX_use_certificate_file(*ctx, servercert.c_str(), SSL_FILETYPE_PEM) <= 0) {
      cout << "Init, SSL_CTX_use_certificate_file failed." << endl;
      return -1;
    }
    cout << "test_gmssl777" << endl;
    // sign private key
    if (SSL_CTX_use_PrivateKey_file(*ctx, serverkey.c_str(), SSL_FILETYPE_PEM) <= 0) {
      cout << "Init, SSL_CTX_use_PrivateKey_file failed." << endl;
      return -1;
    }

    // check sign private key is ok
    if (!SSL_CTX_check_private_key(*ctx)) {
      cout << "Init, SSL_CTX_check_private_key failed." << endl;
      return -1;
    }

    // enc cert
    if (SSL_CTX_use_enc_certificate_file(*ctx, enc_cert.c_str(), SSL_FILETYPE_PEM) <= 0) {
      cout << "Init, SSL_CTX_use_enc_certificate_file failed." << endl;
      return -1;
    }

    // enc private key
    if (SSL_CTX_use_enc_PrivateKey_file(*ctx, enc_key.c_str(), SSL_FILETYPE_PEM) <= 0) {
      cout << "Init, SSL_CTX_use_enc_PrivateKey_file failed." << endl;
      return -1;
    }

    // check enc private key is ok
    if (!SSL_CTX_check_enc_private_key(*ctx)) {
      cout << "Init, SSL_CTX_check_enc_private_key failed." << endl;
      return -1;
    }
  }

  SSL_CTX_set_verify_depth(*ctx, 10);

  cout << "init succeed====" << endl;
  return 0;
}

int main(int argc, char** argv) {
  RunServer(argv);
  // test_gmssl(argv);
  return 0;
}