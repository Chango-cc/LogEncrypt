package com.chango.logencrypt

object UtilConverter {

    fun bytesToInt(bytes: ByteArray): Int {
        return (bytes[3].toInt() shl 24) or
                (bytes[2].toInt() and 0xff shl 16) or
                (bytes[1].toInt() and 0xff shl 8) or
                (bytes[0].toInt() and 0xff)
    }
}