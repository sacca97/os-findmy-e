package com.sacca.openfinder.domain

/**
 * The only thing the UI layers know about where data comes from. Implementation: [com.sacca.openfinder.data.RustOpenFinderBackend]. Failures are thrown as [OpenFinderException]. Nothing here may mention JNI.
 */
interface OpenFinderBackend {
    suspend fun getAuthState(): AuthState
    suspend fun startLogin(username: String, password: String): AuthResult
    suspend fun submitTwoFactor(challengeId: String, code: String): AuthResult
    suspend fun getAccessories(): List<Accessory>
    suspend fun fetchReports(accessoryIds: List<String>): List<LocationReport>
    suspend fun logout()
}
