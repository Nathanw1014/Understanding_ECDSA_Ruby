# Understanding_ECDSA_Ruby

##

This progam was built based around the Ruby ECDSA Library., Ruby was used because of this library.

It uses an insecure implementation of k when signing ECDSA signatures. This should **NEVER** be done in production (just ask Sony..).

This file breaks down some of the ECDSA methods and signatures to help better explain the entire process. 

The current state of this program allows signing of messages/data, and recovering public keys from signatures (with know curves)

Future features will build in private key recovery from insecure implementations of ECDSA that do re-use k. 

The Python implementation of privatekey recovery can be seen here: https://bitcoin.stackexchange.com/questions/35848/recovering-private-key-when-someone-uses-the-same-k-twice-in-ecdsa-signatures
