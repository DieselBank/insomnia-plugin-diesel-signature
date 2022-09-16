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

Sign using stored private key and message on params

### Params
 * hasIdempotencyKey: bool - true is ik needs to be added at start of message
 * fields: string - comma separated keys to append their values to message, values are gotten from, by order:
   * url - if field follows the pattern `$N` then the Nth param on url will be used
   * store - insomnia store
   * body - request body


## UID

Gets last uid returned from an endpoint

### Returns
 * uid

## Transaction Key

Gets last transactionKey returned from an endpoint

### Returns
 * transactionKey
