Design and implementation of log encryption based on RSA&AES
1. Read the RSA public key, randomly generate the AES symmetric key, encrypt the AES key with the RSA public key and write it to the file.
2. Use the AES key to encrypt the log plaintext and then write it to the file.
3. The log content is written in the format of writing the length of 4 bytes first and then the content. Use app/src/test/java/com/chango/logencrypt/DecryptLog.kt to parse the log.

appendix
How to generate RSA keys, see the file app/rsaKey/generateRSA_Key