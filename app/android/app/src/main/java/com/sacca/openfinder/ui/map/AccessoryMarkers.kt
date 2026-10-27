package com.sacca.openfinder.ui.map

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import com.sacca.openfinder.domain.Accessory
import com.sacca.openfinder.domain.AccessoryType
import org.json.JSONArray
import org.json.JSONObject

fun typeColor(type: AccessoryType): Color = when (type) {
    AccessoryType.KEYS -> Color(0xFFE8710A)
    AccessoryType.BAG -> Color(0xFF8E5AD7)
    AccessoryType.BIKE -> Color(0xFF1B9AAA)
    AccessoryType.AIRTAG -> Color(0xFF1E6FD9)
    AccessoryType.WALLET -> Color(0xFFC2185B)
    AccessoryType.CAR -> Color(0xFF2E7D32)
    AccessoryType.PET -> Color(0xFFF9A825)
    AccessoryType.HEADPHONES -> Color(0xFF00897B)
    AccessoryType.LAPTOP -> Color(0xFF5C6BC0)
    AccessoryType.OTHER -> Color(0xFF607D8B)
}

private fun Color.hex(): String = "#%06X".format(0xFFFFFF and toArgb())

/**
 * GeoJSON FeatureCollection text with one point per accessory that has a (valid) report. The properties (id, name,
 * selected, color) drive the layers' data-driven styling.
 */
fun accessoryFeaturesJson(accessories: List<Accessory>, selectedId: String?): String {
    val features = JSONArray()
    for (a in accessories) {
        val r = a.latestReport ?: continue
        features.put(
            JSONObject()
                .put("type", "Feature")
                .put("geometry", JSONObject().put("type", "Point").put("coordinates", JSONArray().put(r.longitude).put(r.latitude)))
                .put("properties", JSONObject().put("id", a.id).put("name", a.name).put("type", a.type.name).put("selected", a.id == selectedId).put("color", typeColor(a.type).hex())),
        )
    }
    return JSONObject().put("type", "FeatureCollection").put("features", features).toString()
}
