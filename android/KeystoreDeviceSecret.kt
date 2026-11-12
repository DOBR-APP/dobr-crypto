package app.dobr.crypto

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Thrown when vaults exist on this phone but the key or salt they depend on
 * has gone. Making fresh ones would quietly hide every existing vault, so
 * Dobr stops and says so instead.
 */
class DeviceSecretLostException : Exception("Device key missing while vaults exist")

/**
 * @param mayCreate asked before generating a missing key. It should return
 *   false when any vault already exists on this phone.
 */
class KeystoreDeviceSecret(private val mayCreate: () -> Boolean) : DeviceSecret {

    override fun mac(data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(key())
        return mac.doFinal(data)
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        if (!mayCreate()) throw DeviceSecretLostException()
        if (Build.VERSION.SDK_INT >= 28) {
            // Prefer the dedicated security chip when the phone has one.
            try {
                return generate(strongBox = true)
            } catch (e: Exception) {
                // No StrongBox on this phone. The regular hardware keystore is fine.
            }
        }
        return generate(strongBox = false)
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
        if (strongBox && Build.VERSION.SDK_INT >= 28) builder.setIsStrongBoxBacked(true)
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")
        generator.init(builder.build())
        return generator.generateKey()
    }

    companion object {
        private const val ALIAS = "dobr_device_hmac_v1"
        private const val PREFS = "dobr_device"

        /**
         * Per-install salt. Clearing app data removes it along with every vault.
         * Saved synchronously, because a salt lost to a crash would orphan the
         * first vault.
         */
        fun salt(context: Context, mayCreate: Boolean): ByteArray {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            prefs.getString("salt", null)?.let { return Base64.decode(it, Base64.NO_WRAP) }
            if (!mayCreate) throw DeviceSecretLostException()
            val salt = ByteArray(32).also { SecureRandom().nextBytes(it) }
            if (!prefs.edit().putString("salt", Base64.encodeToString(salt, Base64.NO_WRAP)).commit()) {
                throw java.io.IOException("Couldn't save the salt")
            }
            return salt
        }
    }
}
