### 不使用证书

- 编译

  在CMakeLists.txt中打开编译greeter_client和greeter_server，执行：

  ```bash
  mkdir build && cd build && cmake ..
  ```

- 运行

  依次启动服务器和客户端：

  ```bash
  ./greeter_server
  ./greeter_client
  ```

  

### OpenSSL使用

- 编译

  在CMakeLists.txt中打开编译ssl_client和ssl_server，执行：

  ```bash
  mkdir build && cd build && cmake ..
  ```

- 生成证书

  ```bash
  cd ssl_key && ./generate.sh
  ```

- 运行

  进入build目录，依次启动服务器和客户端：

  - 服务器

    ```bash
    GRPC_VERBOSITY=INFO ./ssl_server ../ssl_key/ca.crt ../ssl_key/server.key ../ssl_key/server.crt 
    ```

    

  - 客户端

    ```bash
    GRPC_VERBOSITY=INFO ./ssl_client ../ssl_key/server.pem ../ssl_key/client.key ../ssl_key/client.pem 
    ```



### GMSSL使用

- 编译

  在CMakeLists.txt中打开编译gmssl_client和gmssl_server，执行：

  ```bash
  mkdir build && cd build && cmake .. -DUSE_GMTASSL
  ```

- 生成证书

  ```bash
  cd gmssl_key && ./gen_certs_gmssl.sh
  ```

- 运行

  进入build目录，依次启动服务器和客户端：

  - 服务器

    ```bash
     GRPC_VERBOSITY=INFO ./gmssl_server ../gmssl_key/certs/CA.crt ../gmssl_key/certs/SS00.key ../gmssl_key/certs/SS00.crt ../gmssl_key/certs/SE00.key ../gmssl_key/certs/SE00.crt
    ```

    

  - 客户端

    ```bash
     GRPC_VERBOSITY=INFO ./gmssl_client ../gmssl_key/certs/CA.crt ../gmssl_key/certs/CS10.key ../gmssl_key/certs/CS10.crt ../gmssl_key/certs/CE10.key ../gmssl_key/certs/CE10.crt
    ```

    