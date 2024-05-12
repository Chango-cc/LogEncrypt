package com.chango.logencrypt

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith
import java.io.BufferedReader
import java.io.File
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.Locale
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey

@RunWith(AndroidJUnit4::class)
class LogTest {
    @Test
    fun useAppContext() {
        // Context of the app under test.
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        Assert.assertEquals("com.chango.logencrypt", appContext.packageName)
        writeLog(appContext)
    }

    fun writeLog(context: Context) {
        val simpleDateFormat = SimpleDateFormat("MM dd yyyy,HH:mm:ss", Locale.getDefault())
        val plainText =
            "${simpleDateFormat.format(System.currentTimeMillis())} hello world! android RAS, AES! ${System.currentTimeMillis()}, success encrypt." +
                    "作詞：黃偉文     作曲：C.Y.Kong\n" +
                    "\n" +
                    "\n" +
                    "\n" +
                    "有人問我 我就會講 但是無人來\n" +
                    "我期待到無奈 有話要講 得不到裝載\n" +
                    "我的心情猶像樽蓋 等被揭開 咀巴卻在養青苔\n" +
                    "人潮內 愈文靜 愈變得 不受理睬 自己要搞出意外\n" +
                    "\n" +
                    "像突然 地高歌 任何地方也像開四面台\n" +
                    "著最閃的衫 扮十分感慨 有人來拍照要記住插袋\n" +
                    "\n" +
                    "你當我是浮誇吧 誇張只因我很怕\n" +
                    "似木頭 似石頭的話 得到注意嗎\n" +
                    "其實怕被忘記 至放大來演吧\n" +
                    "很不安 怎去優雅\n" +
                    "世上還讚頌沉默嗎\n" +
                    "不夠爆炸 怎麼有話題 讓我誇 做大娛樂家\n" +
                    "\n" +
                    "那年十八 母校舞會 站著如嘍囉\n" +
                    "那時候 我含淚發誓各位 必須看到我\n" +
                    "在世間 平凡又普通的路太多 屋村你住哪一座\n" +
                    "情愛中 工作中 受過的忽視太多 自尊已飽經跌墮\n" +
                    "\n" +
                    "\n" +
                    "重視能治肚餓 末曾獲得過便知我為何\n" +
                    "大動作很多 犯下這些錯\n" +
                    "搏人們看看我 算病態麼\n" +
                    "\n" +
                    "你當我是浮誇吧 誇張只因我很怕\n" +
                    "似木頭 似石頭的話 得到注意嗎\n" +
                    "其實怕被忘記 至放大來演吧\n" +
                    "很不安 怎去優雅\n" +
                    "世上還讚頌沉默嗎\n" +
                    "不夠爆炸 怎麼有話題 讓我誇 做大娛樂家\n" +
                    "\n" +
                    "幸運兒並不多 若然未當過就知我為何\n" +
                    "用十倍苦心做突出一個 正常人夠我富議論性麼\n" +
                    "\n" +
                    "你叫我做浮誇吧 加幾聲噓聲也不怕\n" +
                    "我在場 有悶場的話 表演你看嗎 夠歇斯底里嗎\n" +
                    "以眼淚淋花吧 一心只想你驚訝 我舊時似未存在嗎\n" +
                    "加重注碼 青筋也現形 話我知 現在存在嗎\n" +
                    "\n" +
                    "凝視我 別再只看天花 我非你杯茶\n" +
                    "也可盡情地喝吧 別遺忘有人在 為你 聲沙"

        //1. read RSA public key from file
        val RSA_PublicKey = readPublicKey(context)

        //2. generate random AES key
        val keygen = KeyGenerator.getInstance("AES")
        keygen.init(256)
        val key: SecretKey = keygen.generateKey()
        val encoded = key.encoded

        //3. initial AES Cipher
        val cipherAES: Cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipherAES.init(Cipher.ENCRYPT_MODE, key)
        val iv: ByteArray = cipherAES.iv

        //4. encrypt AES key
        val encryptedAESKey = encryptRSA(RSA_PublicKey, encoded)
        val encryptedIV = encryptRSA(RSA_PublicKey, iv)

        //5. open file output stream
        val fileOutputStream = FileOutputStream(
            File(context.getExternalFilesDir("log"), "log.log").absolutePath,
            true
        )

        //6. write min integer present start
        val startFlag = Int.MIN_VALUE
        val lengthArray = ByteArray(4) { 0 }
        write4BytesToBuffer(lengthArray, startFlag)
        fileOutputStream.write(lengthArray)
        fileOutputStream.flush()

        //7. write key to file
        writeByteArray(fileOutputStream, encryptedAESKey)
        writeByteArray(fileOutputStream, encryptedIV)

        //8. write text to file
        var start = 0
        var end = 0
        val mode = 1024
        for (i in 0..plainText.length / 1024) {
            start += i * mode
            end += (i + 1) * mode
            if (end > plainText.length) {
                end = plainText.length
            }
            val encryptText = encryptAES(cipherAES, plainText.substring(start, end))
            writeByteArray(fileOutputStream, encryptText)
        }

        //9. close file
        fileOutputStream.close()
    }

    fun writeByteArray(fileOutputStream: FileOutputStream, byteArray: ByteArray) {
        val lengthArray = ByteArray(4) { 0 }
        val length = byteArray.size
        write4BytesToBuffer(lengthArray, length)
        fileOutputStream.write(lengthArray)
        fileOutputStream.write(byteArray)
        fileOutputStream.flush()
    }

    fun encryptAES(cipherAES: Cipher, plainText: String): ByteArray {
        val byteArray = plainText.toByteArray()
        val encryptedBytes = cipherAES.doFinal(byteArray)
        return encryptedBytes
    }

    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchPaddingException::class,
        InvalidKeyException::class,
        IllegalBlockSizeException::class,
        BadPaddingException::class
    )
    private fun encryptRSA(publicKey: PublicKey, plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedBytes = cipher.doFinal(plain)
        //assert(encryptedBytes.size < Int.MAX_VALUE)
        return encryptedBytes
    }

    private fun readPublicKey(context: Context): PublicKey {
        val reader = BufferedReader(InputStreamReader(context.assets.open("public.pem")))
        val publicKey = readPublicKey(reader)
        return publicKey
    }

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

    //-------------------------------------- util
    private fun write4BytesToBuffer(buffer: ByteArray, data: Int) {
        buffer[0] = (data shr 0).toByte()
        buffer[1] = (data shr 8).toByte()
        buffer[2] = (data shr 16).toByte()
        buffer[3] = (data shr 24).toByte()
    }
}