## Prerequisites

Generate an RSA public and private key pair using the openssl command-line tool in your terminal. Here's how you can do it:

1. Generate the private key and store it in the `private_key.pem` file.
To generate a 2048-bit RSA private key, use the following command:

```bash
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
```

2. Extract the public key
Once you have the private key, you can generate the corresponding public key into a a `public_key.pem` file with the following command:

```bash
openssl rsa -pubout -in private_key.pem -out public_key.pem
```