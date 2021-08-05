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

using grpc::Channel;
using grpc::ClientContext;
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

class GreeterClient {
 public:
  GreeterClient(std::shared_ptr<Channel> channel)
      : stub_(Greeter::NewStub(channel)) {}

  // Assembles the client's payload, sends it and presents the response back
  // from the server.
  std::string SayHello(const std::string& user) {
    // Data we are sending to the server.
    HelloRequest request;
    request.set_name(user);

    // Container for the data we expect from the server.
    HelloReply reply;

    // Context for the client. It could be used to convey extra information to
    // the server and/or tweak certain RPC behaviors.
    ClientContext context;

    // The actual RPC.
    Status status = stub_->SayHello(&context, request, &reply);

    // Act upon its status.
    if (status.ok()) {
      return reply.message();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return "RPC failed";
    }
  }

 private:
  std::unique_ptr<Greeter::Stub> stub_;
};

int main(int argc, char** argv) {


  auto servercert = argv[1];
  // 签名证书
  auto clientkey  = argv[2];
  auto clientcert = argv[3];

    // 加密证书
  auto enc_key  = argv[4];
  auto enc_cert = argv[5];

  grpc::SslCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs  = servercert;
  ssl_opts.pem_private_key = clientkey;
  ssl_opts.pem_cert_chain  = clientcert;
  ssl_opts.pem_enc_private_key = enc_key;
  ssl_opts.pem_enc_cert_chain = enc_cert;

  std::shared_ptr<grpc::ChannelCredentials> creds = grpc::SslCredentials(ssl_opts);

  std::string server_address("127.0.0.1:50051");
  // std::string server_address("localhost:50051");
  GreeterClient greeter(grpc::CreateChannel(
      server_address, creds));

  std::string user("world, I am GM client");
  std::string reply = greeter.SayHello(user);
  std::cout << "received: " << reply << std::endl;

  return 0;
}
