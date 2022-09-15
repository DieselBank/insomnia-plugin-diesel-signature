# Dieselbank Signature

Insomnia Plugin to sign messages using ed25519

## Generate Signature Keypair

Generates keypair used for signature

### Stores 
 * privKey

### Returns 
 * pubKey

## Generate Idempotency Key

Generates a random idempotency key

### Returns
 * idempotencyKey

## Sign

Sign using stores private key and message on params

### Params
 * hasIdempotencyKey: bool - true is ik needs to be added at start of message
 * fields: string - comma separated body keys to append their values to message
