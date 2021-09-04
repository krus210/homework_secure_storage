package com.otus.securehomework.utils

import android.content.Context
import android.security.KeyPairGeneratorSpec
import android.util.Base64
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.security.auth.x500.X500Principal

class SecurityUtilLowerMImpl @Inject constructor(
    val context: Context
) : SecurityUtil {

    private val FIXED_IV = byteArrayOf(55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44)
    private val rsaCipher by lazy {
        Cipher.getInstance("RSA/ECB/NoPadding")
    }
    private val cipher by lazy {
        Cipher.getInstance("AES/GCM/NoPadding")
    }
    private val charset by lazy {
        charset("UTF-8")

    }
    private val keyStore by lazy {
        KeyStore.getInstance(PROVIDER).apply {
            load(null)
        }
    }
    private val sharedPrefs by lazy { context.getSharedPreferences(PREFS, Context.MODE_PRIVATE) }
    private var encryptedKeyName by StringPrefDelegate(sharedPrefs, ENCRYPTED_KEY_NAME)

    override fun encryptData(keyAlias: String, text: String): ByteArray {
        cipher.init(
            Cipher.ENCRYPT_MODE,
            getAesSecretKey(keyAlias) ?: generateAesSecretKey(keyAlias),
            GCMParameterSpec(
                AUTH_TAG_LENGTH, FIXED_IV
            )
        )
        return cipher.doFinal(text.toByteArray(charset))
    }

    override fun decryptData(keyAlias: String, encryptedData: ByteArray): String {
        cipher.init(
            Cipher.DECRYPT_MODE,
            getAesSecretKey(keyAlias),
            GCMParameterSpec(AUTH_TAG_LENGTH, FIXED_IV)
        )
        return cipher.doFinal(encryptedData).toString(charset)
    }


    private fun getAesSecretKey(keyAlias: String): SecretKey? {
        return encryptedKeyName?.let { keyName ->
            val encryptedKey = Base64.decode(keyName, Base64.DEFAULT)

            val rsaPrivateKey = keyStore.getKey(keyAlias, null) as? PrivateKey
                ?: generateRsaSecretKey(keyAlias).private
            rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey)
            val key = rsaCipher.doFinal(encryptedKey)

            SecretKeySpec(key, AES_ALGORITHM)
        }
    }

    private fun generateAesSecretKey(keyAlias: String): SecretKey {
        val key = ByteArray(16)
        SecureRandom().run { nextBytes(key) }

        val rsaPublicKey =
            keyStore.getCertificate(keyAlias)?.publicKey ?: generateRsaSecretKey(keyAlias).public
        rsaCipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey)
        val rsaEncryptKey = rsaCipher.doFinal(key)

        encryptedKeyName = Base64.encodeToString(rsaEncryptKey, Base64.DEFAULT)
        return SecretKeySpec(key, AES_ALGORITHM)
    }

    private fun generateRsaSecretKey(keyAlias: String): KeyPair {
        val start: Calendar = Calendar.getInstance()
        val end: Calendar = Calendar.getInstance()
        end.add(Calendar.YEAR, 30)
        val spec = KeyPairGeneratorSpec.Builder(context)
            .setAlias(keyAlias)
            .setSubject(X500Principal("CN=$keyAlias"))
            .setSerialNumber(BigInteger.TEN)
            .setStartDate(start.time)
            .setEndDate(end.time)
            .build()
        return KeyPairGenerator.getInstance(RSA_ALGORITHM, PROVIDER).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    companion object {
        private const val ENCRYPTED_KEY_NAME = "RSAEncryptedKeysKeyName"
        private const val PREFS = "PREFS"
        private const val PROVIDER = "AndroidKeyStore"
        private const val RSA_ALGORITHM = "RSA"
        private const val AES_ALGORITHM = "AES"
        const val AUTH_TAG_LENGTH = 128
    }
}