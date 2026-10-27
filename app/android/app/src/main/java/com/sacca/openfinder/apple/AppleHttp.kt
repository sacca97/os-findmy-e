package com.sacca.openfinder.apple

import okhttp3.ConnectionPool
import okhttp3.OkHttpClient
import okhttp3.Protocol
import java.util.concurrent.TimeUnit

/** The one place Apple-facing OkHttp clients are built, so every call verifies against [AppleTls] (system anchors plus Apple's root). */
object AppleHttp {
    fun builder(): OkHttpClient.Builder = AppleTls.apply(OkHttpClient.Builder())

    /**
     * [base] without connection reuse and on HTTP/1.1: what `gsa.apple.com` needs (the Python measured Apple answering 429 when a
     * connection was reused there; its own `urllib` client opens a new connection per request).
     */
    fun unpooled(base: OkHttpClient): OkHttpClient =
        base.newBuilder().connectionPool(ConnectionPool(0, 1, TimeUnit.SECONDS)).protocols(listOf(Protocol.HTTP_1_1)).build()
}
