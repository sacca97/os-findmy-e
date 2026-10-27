package com.sacca.openfinder.ui.components

import androidx.compose.ui.graphics.Color
import com.sacca.openfinder.domain.LocationReport
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale

enum class Freshness(val label: String, val color: Color) {
    FRESH("Recent", Color(0xFF2E9E6B)),
    RECENT("Hours ago", Color(0xFFE0A100)),
    STALE("Old", Color(0xFF8A8F98)),
}

fun freshnessOf(report: LocationReport, now: Instant): Freshness {
    val age = Duration.between(report.observedAt, now)
    return when {
        age < Duration.ofMinutes(15) -> Freshness.FRESH
        age < Duration.ofHours(6) -> Freshness.RECENT
        else -> Freshness.STALE
    }
}

/** "just now", "4 min ago", "3 h ago", "2 days ago": the real age of the report. */
fun relativeAge(observedAt: Instant, now: Instant): String {
    val s = Duration.between(observedAt, now).seconds.coerceAtLeast(0)
    return when {
        s < 60 -> "just now"
        s < 3600 -> "${s / 60} min ago"
        s < 86_400 -> "${s / 3600} h ago"
        else -> "${s / 86_400} day${if (s / 86_400 == 1L) "" else "s"} ago"
    }
}

fun absoluteTime(observedAt: Instant): String =
    DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT)
        .withLocale(Locale.getDefault()).withZone(ZoneId.systemDefault()).format(observedAt)

fun coordinates(report: LocationReport): String =
    String.format(Locale.US, "%.5f, %.5f", report.latitude, report.longitude)

fun accuracyText(meters: Double?): String? = meters?.let { "±${it.toInt()} m" }
