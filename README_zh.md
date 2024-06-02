基于RSA&AES的日志加密设计与实现:
1. 读取RSA公钥，随机生成AES对称密钥，用RSA公钥加密AES密钥写入文件。
2. 使用AES密钥加密日志明文后再写入文件。
3. 日志内容写入按照先写入4个字节的长度，再写入内容的格式。使用 app/src/test/java/com/chango/logencrypt/DecryptLog.kt 可解析日志。

附录:
如何生成RSA密钥见 app/rsaKey/generateRSA_Key