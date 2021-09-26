package com.otus.securehomework.presentation.auth

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.otus.securehomework.biometric.BiometricPromptProvider
import com.otus.securehomework.data.Response
import com.otus.securehomework.data.dto.LoginResponse
import com.otus.securehomework.data.repository.AuthRepository
import com.otus.securehomework.presentation.BaseViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class AuthViewModel
@Inject constructor(
    private val repository: AuthRepository,
    private val biometricPromptProvider: BiometricPromptProvider
) : BaseViewModel(repository) {

    private val _loginResponse: MutableLiveData<Response<LoginResponse>> = MutableLiveData()
    val loginResponse: LiveData<Response<LoginResponse>>
        get() = _loginResponse

    var setAuthWithBiometricPrompt : Boolean =
        biometricPromptProvider.authWithBiometricPrompt

    fun login(
        email: String,
        password: String
    ) = viewModelScope.launch {
        _loginResponse.value = Response.Loading
        _loginResponse.value = repository.login(email, password)
    }

    fun isBiometricPromptEnabled() : Boolean = biometricPromptProvider.isBiometricPromptEnabled()

    suspend fun saveAccessTokens(accessToken: String, refreshToken: String) {
        repository.saveAccessTokens(accessToken, refreshToken)
    }
}