package com.chango.logencrypt

import org.junit.Test
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.FileReader
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class DecryptLog {

    @Test
    fun main() {
        val appDir = System.getProperty("user.dir")!!
        println("path4:$appDir")

        //1. read private Key
        val privateKey = readPrivateKey(appDir)

        //2. decrypt log
        val log = File("$appDir\\rsaKey\\log.log")
        readLog(privateKey, log)
    }

    fun readLog(privateKey: PrivateKey, log: File) {
        println("start...")

        val cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipherRSA.init(Cipher.DECRYPT_MODE, privateKey)

        val cipherAes = Cipher.getInstance("AES/CBC/PKCS5PADDING")

        val fis = FileInputStream(log)

        val lengthArray = ByteArray(4) { 0 }
        val cipherArray = ByteArray(1024 * 1024) { 0 }

        var read: Int
        while (fis.read(lengthArray, 0, 4).also { read = it } != -1) {
            if (read == 0) {
                println("read = 0")
            }
            val length = UtilConverter.bytesToInt(lengthArray)
            if (length == Int.MIN_VALUE) {
                //read AES key
                fis.read(lengthArray, 0, 4)
                val keyLength = UtilConverter.bytesToInt(lengthArray)
                fis.read(cipherArray, 0, keyLength)
                val aesKey = cipherRSA.doFinal(cipherArray, 0, keyLength)
                val secretKeySpec = SecretKeySpec(aesKey, "AES")

                //read AES iv
                fis.read(lengthArray, 0, 4)
                val ivLength = UtilConverter.bytesToInt(lengthArray)
                fis.read(cipherArray, 0, ivLength)
                val iv = cipherRSA.doFinal(cipherArray, 0, ivLength)
                val ivParameterSpec = IvParameterSpec(iv)

                //init AES cipher
                cipherAes.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec)
            } else {
                //decrypt ciphertext
                fis.read(cipherArray, 0, length)
                val plainText = decryptAES(cipherAes, cipherArray, length)

                print(plainText)
            }
        }
        println("end...")
    }

    fun decryptAES(key: ByteArray, ivParameterSpec: IvParameterSpec, encryptedBytes: ByteArray, textLength: Int): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        val secretKeySpec = SecretKeySpec(key, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec)
        val decryptedBytes = cipher.doFinal(encryptedBytes, 0, textLength)
        return String(decryptedBytes)
    }

    fun decryptAES(cipher: Cipher, encryptedBytes: ByteArray, textLength: Int): String {
        val decryptedBytes = cipher.doFinal(encryptedBytes, 0, textLength)
        return String(decryptedBytes)
    }

    private fun readPrivateKey(appDir: String): PrivateKey {
        val privateKeyFile = File("$appDir\\rsaKey\\private.pem")
        val privateKey = readRSAPrivateKey(BufferedReader(FileReader(privateKeyFile)))
        return privateKey
    }

    private fun readRSAPrivateKey(reader: BufferedReader): PrivateKey {
        // Read public key string from PEM file
        val privateKeyPEM = StringBuilder()
        var line: String? = null
        while (reader.readLine()?.also { line = it } != null) {
            if (!line!!.startsWith("-----BEGIN") && !line!!.startsWith("-----END")) {
                privateKeyPEM.append(line)
            }
        }
        reader.close()

        // Decode public key string in PEM format and convert to bytes
        val privateKeyBytes = Base64.getDecoder().decode(privateKeyPEM.toString())

        // Convert bytes to public key object using PKCS8EncodedKeySpec
        val keySpec = PKCS8EncodedKeySpec(privateKeyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        keyFactory.generatePrivate(keySpec)
        val privateKey = keyFactory.generatePrivate(keySpec)
        return privateKey
    }
}