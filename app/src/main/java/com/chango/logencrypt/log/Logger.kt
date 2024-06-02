package com.chango.logencrypt.log

import com.chango.logencrypt.util.KeyUtil
import java.io.File
import java.io.FileOutputStream
import java.security.PublicKey
import javax.crypto.Cipher

class Logger constructor(logFile: File, publicKey: PublicKey) {

    private val fos: FileOutputStream = FileOutputStream(logFile, true)
    private val cipherAES: Cipher
    private val lengthArray = ByteArray(4) { 0 }

    init {
        val aesKey = KeyUtil.generateAESKey()
        cipherAES = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipherAES.init(Cipher.ENCRYPT_MODE, aesKey)

        val encryptedAESKey = KeyUtil.encryptRSA(publicKey, aesKey.encoded)
        val encryptedIV = KeyUtil.encryptRSA(publicKey, cipherAES.iv)

        val startFlag = Int.MIN_VALUE
        intToBytes(lengthArray, startFlag)
        fos.write(lengthArray)
        fos.flush()
        writeByteArray(fos, encryptedAESKey)
        writeByteArray(fos, encryptedIV)
    }

    fun append(plainText: String) {
        var start = 0
        var end = 0
        val mode = 1024
        for (i in 0..plainText.length / mode) {
            start = i * mode
            end = (i + 1) * mode
            if (end > plainText.length) {
                end = plainText.length
            }
            val encryptText = KeyUtil.encryptAES(cipherAES, plainText.substring(start, end))
            writeByteArray(fos, encryptText)
        }
    }

    private fun writeByteArray(fileOutputStream: FileOutputStream, byteArray: ByteArray) {
        val length = byteArray.size
        intToBytes(lengthArray, length)
        fileOutputStream.write(lengthArray)
        fileOutputStream.write(byteArray)
        fileOutputStream.flush()
    }

    private fun intToBytes(bytes: ByteArray, data: Int) {
        bytes[0] = (data shr 0).toByte()
        bytes[1] = (data shr 8).toByte()
        bytes[2] = (data shr 16).toByte()
        bytes[3] = (data shr 24).toByte()
    }
}