package expo.modules.scrypt

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import com.lambdaworks.crypto.SCrypt
import android.util.Base64
import kotlin.math.pow

class ExpoScryptModule : Module() {
    override fun definition() = ModuleDefinition {
        Name("ExpoScrypt")

        AsyncFunction("scrypt") { passwordBase64: String, saltBase64: String, options: Map<String, Int>, callback: Function<Double>? ->
            try {
                // Decode base64 inputs
                val passwordBytes = Base64.decode(passwordBase64, Base64.DEFAULT)
                val saltBytes = Base64.decode(saltBase64, Base64.DEFAULT)

                // Validate null parameters
                if (passwordBytes.isEmpty() || saltBytes.isEmpty()) {
                    throw IllegalArgumentException("Password and salt must not be empty")
                }

                // Validate password and salt lengths
                if (passwordBytes.size > 1024) {
                    throw IllegalArgumentException("Password length must not exceed 1024 bytes")
                }

                if (saltBytes.size < 8 || saltBytes.size > 32) {
                    throw IllegalArgumentException("Salt length must be between 8 and 32 bytes")
                }

                // Extract and validate parameters
                val N = options["N"] ?: throw IllegalArgumentException("N parameter is required")
                val r = options["r"] ?: throw IllegalArgumentException("r parameter is required")
                val p = options["p"] ?: throw IllegalArgumentException("p parameter is required")
                val dkLen = options["dkLen"] ?: throw IllegalArgumentException("dkLen parameter is required")

                // Validate N is a power of 2
                if (N <= 0 || N and (N - 1) != 0) {
                    throw IllegalArgumentException("N must be a power of 2")
                }

                // Validate reasonable bounds
                if (N < 2 || N > 2.0.pow(24).toInt()) {
                    throw IllegalArgumentException("N must be between 2 and 2^24")
                }

                if (r <= 0 || r > 256) {
                    throw IllegalArgumentException("r must be between 1 and 256")
                }

                if (p <= 0 || p > 256) {
                    throw IllegalArgumentException("p must be between 1 and 256")
                }

                if (dkLen <= 0 || dkLen > 64) {
                    throw IllegalArgumentException("dkLen must be between 1 and 64")
                }

                // Check r * p limit
                if (r.toLong() * p.toLong() >= 1L shl 30) {
                    throw IllegalArgumentException("r * p must be less than 2^30")
                }

                val derived = SCrypt.scrypt(
                    passwordBytes,
                    saltBytes,
                    N,
                    r,
                    p,
                    dkLen
                )

                // Report 100% completion if callback is provided
                callback?.invoke(1.0)

                // Return bytes directly as a List<Int>
                derived.map { it.toInt() and 0xFF }
            } catch (e: OutOfMemoryError) {
                throw Exception("Failed to allocate memory for scrypt operation")
            } catch (e: IllegalArgumentException) {
                throw e
            } catch (e: Exception) {
                throw Exception("Scrypt operation failed: ${e.message}")
            }
        }
    }
} 