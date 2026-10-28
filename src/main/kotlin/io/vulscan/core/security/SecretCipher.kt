package io.vulscan.core.security

import io.vulscan.core.config.ScannerProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class EncryptedSecret(val keyVersion: Int, val bytes: ByteArray)

class SecretDecryptionException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/** AES-256-GCM. Формат записи: nonce(12) ‖ ciphertext ‖ tag(16). Nonce случайный для каждой записи. */
class SecretCipher(keyBase64: String, private val keyVersion: Int = 1) {
    private val key: SecretKeySpec? = keyBase64.takeIf { it.isNotBlank() }?.let {
        val raw = Base64.getDecoder().decode(it)
        require(raw.size == 32) { "SCANNER_SECRET_KEY must be 32 bytes (AES-256) in Base64" }
        SecretKeySpec(raw, "AES")
    }
    private val random = SecureRandom()

    fun encrypt(plain: ByteArray): EncryptedSecret {
        val k = requireKey()
        val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, k, GCMParameterSpec(TAG_BITS, nonce))
        return EncryptedSecret(keyVersion, nonce + cipher.doFinal(plain))
    }

    fun decrypt(secret: EncryptedSecret): ByteArray {
        val k = requireKey()
        if (secret.keyVersion != keyVersion) {
            throw SecretDecryptionException("Secret was encrypted with key version ${secret.keyVersion}, but only version $keyVersion is configured")
        }
        if (secret.bytes.size < NONCE_BYTES + TAG_BITS / 8) throw SecretDecryptionException("Encrypted secret is too short")
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(TAG_BITS, secret.bytes.copyOfRange(0, NONCE_BYTES)))
            cipher.doFinal(secret.bytes, NONCE_BYTES, secret.bytes.size - NONCE_BYTES)
        } catch (e: GeneralSecurityException) {
            throw SecretDecryptionException("Secret failed authentication", e)
        }
    }

    private fun requireKey(): SecretKeySpec = key ?: throw IllegalStateException("SCANNER_SECRET_KEY is not configured")

    private companion object {
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val NONCE_BYTES = 12
        const val TAG_BITS = 128
    }
}

@Configuration(proxyBeanMethods = false)
class SecretCipherConfig(private val properties: ScannerProperties) {
    @Bean
    fun secretCipher(): SecretCipher = SecretCipher(properties.secret.keyBase64, properties.secret.keyVersion)
}
