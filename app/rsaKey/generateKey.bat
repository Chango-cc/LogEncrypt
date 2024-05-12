openssl genrsa -out private_PKCS1.pem 1024
openssl pkcs8 -topk8 -inform PEM -in private_PKCS1.pem -outform pem -nocrypt -out private.pem
openssl rsa -in private_PKCS1.pem -pubout -out public.pem