package com.sacca.openfinder.data

import android.content.Context
import com.sacca.openfinder.domain.AccessoryType

/** The icon the user picked for each accessory (by id). Not a secret, so plain preferences. */
class IconStore(context: Context) {
    private val prefs = context.getSharedPreferences("accessory_icons", Context.MODE_PRIVATE)

    fun get(id: String): AccessoryType? = prefs.getString(id, null)?.let { n -> AccessoryType.entries.firstOrNull { it.name == n } }
    fun set(id: String, type: AccessoryType) = prefs.edit().putString(id, type.name).apply()
    fun clear() = prefs.edit().clear().apply()
}
