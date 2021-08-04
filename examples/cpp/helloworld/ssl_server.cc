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

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using helloworld::HelloRequest;
using helloworld::HelloReply;
using helloworld::Greeter;
using namespace std;

const char clientcert_path[] = "./ssl_key/client_self_signed_crt.pem";
const char servercert_path[] = "./ssl_key/server_self_signed_crt.pem";
const char serverkey_path[]  = "./ssl_key/server_privatekey.pem";

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
    std::string prefix("Hello ");
    reply->set_message(prefix + request->name());
    return Status::OK;
  }
};

void RunServer(char** argv) {
  // std::string server_address("localhost:50051");
  // std::string server_address("192.168.21.126:50051");
  // std::string server_address("0.0.0.0:50051");
  std::string server_address("127.0.0.1:50051");
  
  GreeterServiceImpl service;

  // auto root_crt = get_file_contents(clientcert_path); // for verifying clients
  // auto servercert = get_file_contents(servercert_path);
  // auto serverkey  = get_file_contents(serverkey_path);

  auto root_crt = get_file_contents(argv[1]); // for verifying clients
  auto serverkey  = get_file_contents(argv[2]);
  auto servercert = get_file_contents(argv[3]);

  grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp = {
    serverkey.c_str(), servercert.c_str()
  };

  grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
  ssl_opts.pem_root_certs = root_crt;
  ssl_opts.pem_key_cert_pairs.push_back(pkcp);
  ssl_opts.is_gmssl = true;
  
  std::shared_ptr<grpc::ServerCredentials> creds;
  creds = grpc::SslServerCredentials(ssl_opts);
  
  ServerBuilder builder;
  
  builder.AddListeningPort(server_address, creds);
  
  builder.RegisterService(&service);
  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

int main(int argc, char** argv) {
  RunServer(argv);

  return 0;
}
