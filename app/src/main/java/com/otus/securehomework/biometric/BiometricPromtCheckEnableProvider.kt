package com.otus.securehomework.biometric

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import androidx.biometric.BiometricManager
import com.otus.securehomework.utils.BooleanPrefDelegate
import javax.inject.Inject

class BiometricPromptProvider @Inject constructor(
    context: Context,
    sharedPreferences: SharedPreferences
) {
    var authWithBiometricPrompt by BooleanPrefDelegate(
        sharedPreferences,
        AUTH_WITH_BIOMETRIC_PROMPT
    )
    val biometricManager by lazy { BiometricManager.from(context) }

    fun isBiometricPromptEnabled() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M

    private companion object {
        const val AUTH_WITH_BIOMETRIC_PROMPT = "AUTH_WITH_BIOMETRIC_PROMPT"
    }

}