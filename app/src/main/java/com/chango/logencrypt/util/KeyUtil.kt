package com.chango.logencrypt.util

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object KeyUtil {

    // RSA ----------------------------------------
    private fun readPublicKey(reader: BufferedReader): PublicKey {
        // Read public key string from PEM file
        val publicKeyPEM = StringBuilder()
        var line: String? = null
        while (reader.readLine()?.also { line = it } != null) {
            if (!line!!.startsWith("-----BEGIN PUBLIC KEY-----") && !line!!.startsWith("-----END PUBLIC KEY-----")) {
                publicKeyPEM.append(line)
            }
        }
        reader.close()

        // Decode public key string in PEM format and convert to bytes
        val publicKeyBytes = java.util.Base64.getDecoder().decode(publicKeyPEM.toString())

        // Convert bytes to public key object using X509EncodedKeySpec class
        val keySpec = X509EncodedKeySpec(publicKeyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        val publicKey = keyFactory.generatePublic(keySpec)
        return publicKey
    }

    fun readRSAPublicKeyFromFile(context: Context): PublicKey {
        val reader = BufferedReader(InputStreamReader(context.assets.open("public.pem")))
        val publicKey = readPublicKey(reader)
        return publicKey
    }

    fun encryptRSA(publicKey: PublicKey, plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedBytes = cipher.doFinal(plain)
        return encryptedBytes
    }


    // AES ----------------------------------------
    fun generateAESKey(): SecretKey {
        val keygen = KeyGenerator.getInstance("AES")
        keygen.init(256)
        val key: SecretKey = keygen.generateKey()
        return key
    }

    fun encryptAES(cipherAES: Cipher, plainText: String): ByteArray {
        val byteArray = plainText.toByteArray()
        val encryptedBytes = cipherAES.doFinal(byteArray)
        return encryptedBytes
    }
}