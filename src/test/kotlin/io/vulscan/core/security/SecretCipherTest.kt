package io.vulscan.core.security

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.util.Base64

class SecretCipherTest {
    private val key = Base64.getEncoder().encodeToString(ByteArray(32) { it.toByte() })
    private val cipher = SecretCipher(key, 1)

    @Test
    fun `round trip`() {
        val plain = """{"password":"p@ss"}""".toByteArray()
        assertThat(cipher.decrypt(cipher.encrypt(plain))).isEqualTo(plain)
    }

    @Test
    fun `same plaintext gives different ciphertext`() {
        val plain = "same".toByteArray()
        assertThat(cipher.encrypt(plain).bytes).isNotEqualTo(cipher.encrypt(plain).bytes)
    }

    @Test
    fun `tampering is detected`() {
        val encrypted = cipher.encrypt("secret".toByteArray())
        encrypted.bytes[encrypted.bytes.size - 1] = (encrypted.bytes.last().toInt() xor 1).toByte()
        assertThatThrownBy { cipher.decrypt(encrypted) }.isInstanceOf(SecretDecryptionException::class.java)
    }

    @Test
    fun `unknown key version gives a clear error`() {
        val encrypted = EncryptedSecret(7, cipher.encrypt("x".toByteArray()).bytes)
        assertThatThrownBy { cipher.decrypt(encrypted) }.hasMessageContaining("key version 7")
    }

    @Test
    fun `wrong key cannot decrypt`() {
        val other = SecretCipher(Base64.getEncoder().encodeToString(ByteArray(32) { 9 }), 1)
        assertThatThrownBy { other.decrypt(cipher.encrypt("x".toByteArray())) }.isInstanceOf(SecretDecryptionException::class.java)
    }

    @Test
    fun `missing key fails on use and short key fails fast`() {
        assertThatThrownBy { SecretCipher("").encrypt("x".toByteArray()) }.isInstanceOf(IllegalStateException::class.java)
        assertThatThrownBy { SecretCipher(Base64.getEncoder().encodeToString(ByteArray(16))) }.isInstanceOf(IllegalArgumentException::class.java)
    }
}
