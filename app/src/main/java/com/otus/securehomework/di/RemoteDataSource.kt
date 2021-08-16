package com.otus.securehomework.di

import com.otus.securehomework.BuildConfig
import com.otus.securehomework.data.source.network.TokenRefreshApi
import okhttp3.Authenticator
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory

private const val BASE_URL = "http://simplifiedcoding.tech/mywebapp/public/api/"

fun <Api> buildApi(
    api: Class<Api>,
    authenticator: Authenticator
): Api {
    return Retrofit.Builder()
        .baseUrl(BASE_URL)
        .client(getRetrofitClient(authenticator))
        .addConverterFactory(GsonConverterFactory.create())
        .build()
        .create(api)
}

fun buildTokenApi(): TokenRefreshApi {
    return Retrofit.Builder()
        .baseUrl(BASE_URL)
        .client(getRetrofitClient())
        .addConverterFactory(GsonConverterFactory.create())
        .build()
        .create(TokenRefreshApi::class.java)
}

private fun getRetrofitClient(authenticator: Authenticator? = null): OkHttpClient {
    return OkHttpClient.Builder()
        .addInterceptor { chain ->
            chain.proceed(chain.request().newBuilder().also {
                it.addHeader("Accept", "application/json")
            }.build())
        }.also { client ->
            authenticator?.let { client.authenticator(it) }
            if (BuildConfig.DEBUG) {
                val logging = HttpLoggingInterceptor()
                logging.setLevel(HttpLoggingInterceptor.Level.BODY)
                client.addInterceptor(logging)
            }
        }.build()
}