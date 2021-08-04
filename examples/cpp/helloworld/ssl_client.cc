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

const char servercert_path[] = "./ssl_key/server_self_signed_crt.pem";
const char clientcert_path[] = "./ssl_key/client_self_signed_crt.pem";
const char clientkey_path[]  = "./ssl_key/client_privatekey.pem";

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
  // Instantiate the client. It requires a channel, out of which the actual RPCs
  // are created. This channel models a connection to an endpoint (in this case,
  // localhost at port 50051). We indicate that the channel isn't authenticated
  // (use of InsecureChannelCredentials()).

  // auto servercert = get_file_contents(servercert_path);
  // auto clientkey  = get_file_contents(clientkey_path);
  // auto clientcert = get_file_contents(clientcert_path);

  const char* test = "";
  std::string str(test);
  std::cout << "test=========" << str << std::endl;

  auto servercert = get_file_contents(argv[1]);
  auto clientkey  = get_file_contents(argv[2]);
  auto clientcert = get_file_contents(argv[3]);


  grpc::SslCredentialsOptions ssl_opts;
  ssl_opts.pem_root_certs  = servercert;
  ssl_opts.pem_private_key = clientkey;
  ssl_opts.pem_cert_chain  = clientcert;

  std::shared_ptr<grpc::ChannelCredentials> creds = grpc::SslCredentials(ssl_opts);

  // std::string server_address("192.168.21.126:50051");
  std::string server_address("127.0.0.1:50051");
  // std::string server_address("192.168.21.126:50051");
  GreeterClient greeter(grpc::CreateChannel(
      server_address, creds));
  std::string user("world, I am client1");
  std::string reply = greeter.SayHello(user);
  std::cout << "Greeter received: " << reply << std::endl;

  return 0;
}
