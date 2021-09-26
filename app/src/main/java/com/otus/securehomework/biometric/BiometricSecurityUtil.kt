package com.otus.securehomework.biometric

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricPrompt
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject

@RequiresApi(Build.VERSION_CODES.M)
class BiometricSecurityUtil @Inject constructor(
    private val context : Context
) {

    private val keyAlias by lazy { "${context.packageName}.biometricKey" }
    private val charset by lazy {
        charset("UTF-8")
    }

    fun getEncryptor(): BiometricPrompt.CryptoObject {
        val encryptor = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        }

        return BiometricPrompt.CryptoObject(encryptor)
    }

    fun getDecryptor(iv: ByteArray): BiometricPrompt.CryptoObject {
        val decryptor = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(AUTH_TAG_SIZE, iv))
        }
        return BiometricPrompt.CryptoObject(decryptor)
    }

    fun encrypt(plaintext: String, encryptor: Cipher): ByteArray {
        require(plaintext.isNotEmpty()) { "Plaintext cannot be empty" }
        return encryptor.doFinal(plaintext.toByteArray(charset))
    }

    fun decrypt(ciphertext: ByteArray, decryptor: Cipher): String {
        return decryptor.doFinal(ciphertext).toString(charset)
    }

    private fun getOrCreateKey(): SecretKey {
        val keystore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply {
            load(null)
        }

        keystore.getKey(keyAlias, null)?.let { key ->
            return key as SecretKey
        }

        val keySpec = KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_SIZE)
            .setUserAuthenticationRequired(true)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setUnlockedDeviceRequired(true)

                    val hasStringBox = context
                        .packageManager
                        .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

                    setIsStrongBoxBacked(hasStringBox)
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                }
            }.build()

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER).apply {
            init(keySpec)
        }

        return keyGenerator.generateKey()
    }

    private companion object {
        const val TRANSFORMATION = "${KeyProperties.KEY_ALGORITHM_AES}/" +
                "${KeyProperties.BLOCK_MODE_GCM}/" +
                "${KeyProperties.ENCRYPTION_PADDING_NONE}"
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val KEY_SIZE = 256
        const val AUTH_TAG_SIZE = 128
    }

}