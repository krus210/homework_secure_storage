package com.otus.securehomework.utils

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties.*
import androidx.annotation.RequiresApi
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.inject.Inject

@RequiresApi(Build.VERSION_CODES.M)
class SecurityUtilImpl @Inject constructor() : SecurityUtil {

    private val FIXED_IV = byteArrayOf(55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44)
    private val provider = "AndroidKeyStore"
    private val cipher by lazy {
        Cipher.getInstance("AES/GCM/NoPadding")
    }
    private val charset by lazy {
        charset("UTF-8")

    }
    private val keyStore by lazy {
        KeyStore.getInstance(provider).apply {
            load(null)
        }
    }
    private val keyGenerator by lazy {
        KeyGenerator.getInstance(KEY_ALGORITHM_AES, provider)
    }

    override fun encryptData(keyAlias: String, text: String): ByteArray {
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(keyAlias), GCMParameterSpec(96, FIXED_IV))
        return cipher.doFinal(text.toByteArray(charset))
    }

    override fun decryptData(keyAlias: String, encryptedData: ByteArray): String {
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(keyAlias), GCMParameterSpec(96, FIXED_IV))
        return cipher.doFinal(encryptedData).toString(charset)
    }

    private fun generateSecretKey(keyAlias: String): SecretKey {
        return keyGenerator.apply {
            init(
                KeyGenParameterSpec
                    .Builder(keyAlias, PURPOSE_ENCRYPT or PURPOSE_DECRYPT)
                    .setBlockModes(BLOCK_MODE_GCM)
                    .setEncryptionPaddings(ENCRYPTION_PADDING_NONE)
                    .build()
            )
        }.generateKey()
    }

    private fun getSecretKey(keyAlias: String) =
        keyStore.getKey(keyAlias, null) as? SecretKey ?: generateSecretKey(keyAlias)
}