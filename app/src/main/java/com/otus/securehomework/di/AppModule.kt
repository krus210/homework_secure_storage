package com.otus.securehomework.di

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import com.otus.securehomework.data.repository.AuthRepository
import com.otus.securehomework.data.repository.TokenAuthenticator
import com.otus.securehomework.data.repository.UserRepository
import com.otus.securehomework.data.source.local.UserPreferences
import com.otus.securehomework.data.source.network.AuthApi
import com.otus.securehomework.data.source.network.TokenRefreshApi
import com.otus.securehomework.data.source.network.UserApi
import com.otus.securehomework.utils.SecurityUtil
import com.otus.securehomework.utils.SecurityUtilImpl
import com.otus.securehomework.utils.SecurityUtilLowerMImpl
import dagger.Module
import dagger.Provides
import dagger.Reusable
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import okhttp3.Authenticator
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideTokenApi() = buildTokenApi()

    @Provides
    @Singleton
    fun provideAuthenticator(
        tokenApi: TokenRefreshApi,
        userPreferences: UserPreferences
    ): Authenticator =
        TokenAuthenticator(tokenApi, userPreferences)

    @Provides
    fun provideAuthApi(
        authenticator: Authenticator
    ): AuthApi {
        return buildApi(AuthApi::class.java, authenticator)
    }

    @Provides
    fun provideUserApi(
        authenticator: Authenticator
    ): UserApi {
        return buildApi(UserApi::class.java, authenticator)
    }

    @Singleton
    @Provides
    fun provideUserPreferences(
        @ApplicationContext context: Context,
        securityUtil: SecurityUtil
    ): UserPreferences {
        return UserPreferences(context, securityUtil)
    }

    @Provides
    fun provideAuthRepository(
        authApi: AuthApi,
        userPreferences: UserPreferences
    ): AuthRepository {
        return AuthRepository(authApi, userPreferences)
    }

    @Provides
    fun provideUserRepository(
        userApi: UserApi
    ): UserRepository {
        return UserRepository(userApi)
    }

    @Provides
    @Reusable
    fun providesSecurityUtil(@ApplicationContext applicationContext: Context, sharedPreferences: SharedPreferences): SecurityUtil =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) SecurityUtilImpl()
        else SecurityUtilLowerMImpl(applicationContext, sharedPreferences)

    @Provides
    @Reusable
    fun provideTokenAuthenticator(tokenApi: TokenRefreshApi, userPreferences: UserPreferences) =
        TokenAuthenticator(tokenApi, userPreferences)

    @Provides
    @Reusable
    fun providePrefs(@ApplicationContext applicationContext: Context): SharedPreferences =
        applicationContext.getSharedPreferences("PREFS", Context.MODE_PRIVATE)
}