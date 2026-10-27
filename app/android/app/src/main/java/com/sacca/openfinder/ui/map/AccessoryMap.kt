package com.sacca.openfinder.ui.map

import android.annotation.SuppressLint
import android.graphics.RectF
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import android.os.Bundle
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.sacca.openfinder.domain.Accessory
import androidx.compose.ui.graphics.toArgb
import com.sacca.openfinder.domain.AccessoryType
import org.maplibre.android.MapLibre
import org.maplibre.android.camera.CameraPosition
import org.maplibre.android.camera.CameraUpdateFactory
import org.maplibre.android.geometry.LatLng
import org.maplibre.android.geometry.LatLngBounds
import org.maplibre.android.maps.MapLibreMap
import org.maplibre.android.maps.MapView
import org.maplibre.android.maps.Style
import org.maplibre.android.style.expressions.Expression
import org.maplibre.android.style.layers.CircleLayer
import org.maplibre.android.style.layers.Property
import org.maplibre.android.style.layers.PropertyFactory.iconAllowOverlap
import org.maplibre.android.style.layers.PropertyFactory.iconIgnorePlacement
import org.maplibre.android.style.layers.PropertyFactory.iconImage
import org.maplibre.android.style.layers.PropertyFactory.circleColor
import org.maplibre.android.style.layers.PropertyFactory.circleOpacity
import org.maplibre.android.style.layers.PropertyFactory.circleRadius
import org.maplibre.android.style.layers.PropertyFactory.circleStrokeColor
import org.maplibre.android.style.layers.PropertyFactory.circleStrokeWidth
import org.maplibre.android.style.layers.PropertyFactory.textAnchor
import org.maplibre.android.style.layers.PropertyFactory.textColor
import org.maplibre.android.style.layers.PropertyFactory.textField
import org.maplibre.android.style.layers.PropertyFactory.textFont
import org.maplibre.android.style.layers.PropertyFactory.textHaloColor
import org.maplibre.android.style.layers.PropertyFactory.textHaloWidth
import org.maplibre.android.style.layers.PropertyFactory.textOffset
import org.maplibre.android.style.layers.PropertyFactory.textOptional
import org.maplibre.android.style.layers.PropertyFactory.textSize
import org.maplibre.android.style.layers.SymbolLayer
import org.maplibre.android.style.sources.GeoJsonSource

/** Map styles (OpenFreeMap). Configurable: the settings screen can later offer more. */
object MapStyles {
    const val LIBERTY = "https://tiles.openfreemap.org/styles/liberty"
    const val DARK_ASSET = "map_style_dark.json"
}

private const val SOURCE_ID = "accessories"
private const val DOT_LAYER = "accessory-dot"

/**
 * The map, independent of login and report retrieval: it only renders [accessories] from state. Markers are GeoJSON
 * features in ONE source with three layers (selection halo, colored dot, name label): no Android view per marker.
 * The MapView is created once and survives data changes; only the source's data is replaced. Built on the stable
 * MapLibre Native Android SDK inside AndroidView; the signature is the abstraction the rest of the app depends on.
 */
@SuppressLint("MissingPermission")
@Composable
fun AccessoryMap(
    accessories: List<Accessory>,
    selectedId: String?,
    fitAllTick: Int,
    darkTheme: Boolean,
    viewportInsets: PaddingValues,
    onAccessoryClick: (String) -> Unit,
    showMyLocation: Boolean = false,
    locateTick: Int = 0,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val density = LocalDensity.current
    val layoutDirection = LocalLayoutDirection.current
    val features = remember(accessories, selectedId) { accessoryFeaturesJson(accessories, selectedId) }
    val positioned = remember(accessories) { accessories.mapNotNull { a -> a.latestReport?.let { a.id to it } } }
    val onClick by rememberUpdatedState(onAccessoryClick)

    val mapView = remember {
        MapLibre.getInstance(context)
        MapView(context)
    }
    var map by remember { mutableStateOf<MapLibreMap?>(null) }
    var styleLoaded by remember { mutableStateOf(false) }
    val latestFeatures by rememberUpdatedState(features)

    // MapView needs the host's lifecycle forwarded.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner, mapView) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_CREATE -> mapView.onCreate(null as Bundle?)
                Lifecycle.Event.ON_START -> mapView.onStart()
                Lifecycle.Event.ON_RESUME -> mapView.onResume()
                Lifecycle.Event.ON_PAUSE -> mapView.onPause()
                Lifecycle.Event.ON_STOP -> mapView.onStop()
                Lifecycle.Event.ON_DESTROY -> mapView.onDestroy()
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        // The host may already be past ON_CREATE when this composable enters composition.
        val state = lifecycleOwner.lifecycle.currentState
        if (state.isAtLeast(Lifecycle.State.CREATED)) mapView.onCreate(null as Bundle?)
        if (state.isAtLeast(Lifecycle.State.STARTED)) mapView.onStart()
        if (state.isAtLeast(Lifecycle.State.RESUMED)) mapView.onResume()
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            mapView.onPause(); mapView.onStop(); mapView.onDestroy()
        }
    }

    // One-time map setup: camera start, gestures, marker taps.
    LaunchedEffect(mapView) {
        mapView.getMapAsync { m ->
            map = m
            m.uiSettings.isCompassEnabled = false
            m.uiSettings.isRotateGesturesEnabled = false
            m.cameraPosition = CameraPosition.Builder().target(LatLng(43.61, 7.07)).zoom(9.0).build()
            m.addOnMapClickListener { latLng ->
                val p = m.projection.toScreenLocation(latLng)
                val r = 28f * density.density
                val hit = m.queryRenderedFeatures(RectF(p.x - r, p.y - r, p.x + r, p.y + r), DOT_LAYER).firstOrNull()
                val id = hit?.getStringProperty("id")
                if (id != null) { onClick(id); true } else false
            }
        }
    }

    // Style (and its marker layers) follows the theme; the source starts with the data we already have.
    val appContext = androidx.compose.ui.platform.LocalContext.current.applicationContext
    LaunchedEffect(map, darkTheme) {
        val m = map ?: return@LaunchedEffect
        styleLoaded = false
        val builder = if (darkTheme) {
            // Google-Maps-like night palette, generated from Liberty by tools/gen_dark_style.py.
            val json = withContext(Dispatchers.IO) { appContext.assets.open(MapStyles.DARK_ASSET).use { String(it.readBytes()) } }
            Style.Builder().fromJson(json)
        } else Style.Builder().fromUri(MapStyles.LIBERTY)
        m.setStyle(builder) { style ->
            installMarkerLayers(style, latestFeatures, darkTheme)
            styleLoaded = true
        }
    }

    // Data changes (refresh, selection): replace the source's data. No map or style rebuild.
    LaunchedEffect(features, styleLoaded) {
        if (!styleLoaded) return@LaunchedEffect
        map?.style?.getSourceAs<GeoJsonSource>(SOURCE_ID)?.setGeoJson(features)
    }

    // "You are here": the SDK's location component (blue dot), only once the permission is granted.
    LaunchedEffect(map, styleLoaded, showMyLocation) {
        val m = map ?: return@LaunchedEffect
        val style = m.style ?: return@LaunchedEffect
        if (!styleLoaded || !showMyLocation) return@LaunchedEffect
        val lc = m.locationComponent
        if (!lc.isLocationComponentActivated) {
            lc.activateLocationComponent(org.maplibre.android.location.LocationComponentActivationOptions.builder(context, style).build())
        }
        lc.isLocationComponentEnabled = true
        lc.cameraMode = org.maplibre.android.location.modes.CameraMode.NONE
        lc.renderMode = org.maplibre.android.location.modes.RenderMode.COMPASS
    }

    // The "my location" button: fly to the last known fix.
    LaunchedEffect(locateTick) {
        val m = map ?: return@LaunchedEffect
        if (locateTick == 0 || !showMyLocation || !m.locationComponent.isLocationComponentActivated) return@LaunchedEffect
        val loc = m.locationComponent.lastKnownLocation ?: return@LaunchedEffect
        m.animateCamera(CameraUpdateFactory.newLatLngZoom(LatLng(loc.latitude, loc.longitude), maxOf(m.cameraPosition.zoom, 15.0)), 700)
    }

    // Keep the camera's usable area clear of the translucent top bar and the bottom sheet.
    LaunchedEffect(map, viewportInsets) {
        val m = map ?: return@LaunchedEffect
        val top = with(density) { viewportInsets.calculateTopPadding().roundToPx() }
        val bottom = with(density) { viewportInsets.calculateBottomPadding().roundToPx() }
        m.setPadding(0, top, 0, bottom)
        // Keep the logo and attribution above the sheet's peek.
        m.uiSettings.setLogoMargins(density.dpPxInt(8), 0, 0, bottom + density.dpPxInt(8))
        m.uiSettings.setAttributionMargins(density.dpPxInt(96), 0, 0, bottom + density.dpPxInt(8))
    }

    // Selection: fly to the accessory, never zooming out when already close.
    LaunchedEffect(selectedId, map) {
        val m = map ?: return@LaunchedEffect
        val r = positioned.firstOrNull { it.first == selectedId }?.second ?: return@LaunchedEffect
        val zoom = maxOf(m.cameraPosition.zoom, 15.0)
        m.animateCamera(CameraUpdateFactory.newLatLngZoom(LatLng(r.latitude, r.longitude), zoom), 700)
    }

    // Fit all: once when the first positions arrive, and whenever the user asks (tick).
    val hasData = positioned.isNotEmpty()
    LaunchedEffect(fitAllTick, hasData, map) {
        val m = map ?: return@LaunchedEffect
        if (!hasData) return@LaunchedEffect
        val reports = positioned.map { it.second }
        if (reports.size == 1) {
            m.animateCamera(CameraUpdateFactory.newLatLngZoom(LatLng(reports[0].latitude, reports[0].longitude), 14.0), 700)
        } else {
            val bounds = LatLngBounds.Builder().apply { reports.forEach { include(LatLng(it.latitude, it.longitude)) } }.build()
            m.animateCamera(CameraUpdateFactory.newLatLngBounds(bounds, density.dpPxInt(56)), 900)
        }
    }

    AndroidView(factory = { mapView }, modifier = modifier)
}

private fun androidx.compose.ui.unit.Density.dpPxInt(dp: Int): Int = (dp * density).toInt()

private fun installMarkerLayers(style: Style, features: String, dark: Boolean) {
    style.addSource(GeoJsonSource(SOURCE_ID, features))
    val labelText = if (dark) "#FFFFFF" else "#1B1B1F"
    val labelHalo = if (dark) "#1B1B1F" else "#FFFFFF"
    // Halo behind the selected accessory.
    style.addLayer(
        CircleLayer("accessory-halo", SOURCE_ID).withProperties(
            circleRadius(26f), circleColor("#1E6FD9"), circleOpacity(0.22f),
            circleStrokeColor("#1E6FD9"), circleStrokeWidth(2f),
        ).withFilter(Expression.eq(Expression.get("selected"), Expression.literal(true))),
    )
    // The marker: the accessory's icon (emoji on a colored disc, drawn once per type), picked by the "type" property.
    AccessoryType.entries.forEach { t -> style.addImage("icon-${t.name}", markerBitmap(t)) }
    style.addLayer(
        SymbolLayer(DOT_LAYER, SOURCE_ID).withProperties(
            iconImage(Expression.concat(Expression.literal("icon-"), Expression.get("type"))),
            iconAllowOverlap(true), iconIgnorePlacement(true),
        ),
    )
    style.addLayer(
        SymbolLayer("accessory-label", SOURCE_ID).withProperties(
            textField(Expression.get("name")), textFont(arrayOf("Noto Sans Regular")), textSize(12f),
            textColor(labelText), textHaloColor(labelHalo), textHaloWidth(1.5f),
            textOffset(arrayOf(0f, 1.9f)), textAnchor(Property.TEXT_ANCHOR_TOP), textOptional(true),
        ),
    )
}

/** A round marker: the type's color, a white ring and its emoji, 40 dp at the screen's density. */
private fun markerBitmap(type: AccessoryType): android.graphics.Bitmap {
    val px = 96
    val bmp = android.graphics.Bitmap.createBitmap(px, px, android.graphics.Bitmap.Config.ARGB_8888)
    val c = android.graphics.Canvas(bmp)
    val p = android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG)
    p.color = android.graphics.Color.WHITE
    c.drawCircle(px / 2f, px / 2f, px / 2f, p)
    p.color = typeColor(type).toArgb()
    c.drawCircle(px / 2f, px / 2f, px / 2f - 6f, p)
    p.textSize = px * 0.5f
    p.textAlign = android.graphics.Paint.Align.CENTER
    val y = px / 2f - (p.descent() + p.ascent()) / 2f
    c.drawText(type.emoji, px / 2f, y, p)
    return bmp
}
