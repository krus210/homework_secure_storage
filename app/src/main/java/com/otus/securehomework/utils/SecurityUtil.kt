package com.otus.securehomework.utils

interface SecurityUtil {
    fun encryptData(keyAlias: String, text: String): ByteArray
    fun decryptData(keyAlias: String, encryptedData: ByteArray): String
}