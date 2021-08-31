package com.otus.securehomework.data.source.local

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.otus.securehomework.utils.SecurityUtil
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import javax.inject.Inject

class UserPreferences
@Inject constructor(
    private val context: Context,
    private val securityUtil: SecurityUtil
) {
    private val Context.dataStore by preferencesDataStore(name = dataStoreFile)
    private val json = Json { encodeDefaults = true }

    val accessToken: Flow<String?>
        get() = context.dataStore.data.secureMap { preferences ->
            preferences[ACCESS_TOKEN].orEmpty()
        }

    val refreshToken: Flow<String?>
        get() = context.dataStore.data.secureMap { preferences ->
            preferences[REFRESH_TOKEN].orEmpty()
        }

    suspend fun saveAccessTokens(accessToken: String?, refreshToken: String?) {
        context.dataStore.secureEdit(accessToken) { preferences, encryptedValue ->
            preferences[ACCESS_TOKEN] = encryptedValue
        }
        context.dataStore.secureEdit(refreshToken) { preferences, encryptedValue ->
            preferences[REFRESH_TOKEN] = encryptedValue
        }
    }

    suspend fun clear() {
        context.dataStore.edit { preferences ->
            preferences.clear()
        }
    }

    private suspend inline fun <reified T> DataStore<Preferences>.secureEdit(
        value: T,
        crossinline editStore: (MutablePreferences, String) -> Unit
    ) {
        edit {
            val encryptedValue =
                securityUtil.encryptData(SECURITY_KEY_ALIAS, Json.encodeToString(value))
            editStore.invoke(it, encryptedValue.joinToString("|"))
        }
    }

    private inline fun <reified T> Flow<Preferences>.secureMap(crossinline fetchValue: (value: Preferences) -> String): Flow<T?> {
        return map {
            val fetchValueResult =
                checkNotNull(fetchValue(it).takeIf { value -> value.isNotEmpty() }) { return@map null }

            val decryptedValue = securityUtil.decryptData(
                SECURITY_KEY_ALIAS,
                fetchValueResult.split("|").map { values -> values.toByte() }.toByteArray()
            )
            json.decodeFromString(decryptedValue)
        }
    }

    companion object {
        private const val SECURITY_KEY_ALIAS = "data-store"
        private const val dataStoreFile: String = "securePref"
        private val ACCESS_TOKEN = stringPreferencesKey("key_access_token")
        private val REFRESH_TOKEN = stringPreferencesKey("key_refresh_token")
    }
}