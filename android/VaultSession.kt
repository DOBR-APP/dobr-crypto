package app.dobr.session

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.LruCache
import androidx.compose.ui.graphics.ImageBitmap
import app.dobr.vault.VaultItem
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File

class OpenVault(val vaultId: String, val encKey: ByteArray, val isNew: Boolean)

/**
 * The only place an unlocked key lives. Locking zeroes the key, drops cached
 * previews and wipes any temporary decrypted copies.
 *
 * Locking rules:
 *  - Leaving Dobr locks it straight away.
 *  - Turning the screen off locks it straight away, whatever else is going on.
 *  - The one exception is a picker, purchase sheet or "Open with" that Dobr itself
 *    launched. Those get [EXTERNAL_GRACE_MS] to come back before the vault locks.
 *    The exception ends the moment Dobr's own screen is back in front.
 */
object VaultSession {
    private val _open = MutableStateFlow<OpenVault?>(null)
    val open: StateFlow<OpenVault?> = _open.asStateFlow()

    private val _items = MutableStateFlow<List<VaultItem>>(emptyList())
    val items: StateFlow<List<VaultItem>> = _items.asStateFlow()

    /** A sixth of the app's memory, at most 64 MB. */
    private val THUMB_CACHE_BYTES = (Runtime.getRuntime().maxMemory() / 6).coerceAtMost(64L * 1024 * 1024).toInt()

    /** Decoded previews, sized by memory rather than count so big vaults stay within budget. */
    val thumbs = object : LruCache<String, ImageBitmap>(THUMB_CACHE_BYTES) {
        override fun sizeOf(key: String, value: ImageBitmap) = value.width * value.height * 4
    }

    /** Folder for files handed to another app with "Open with". Wiped on lock. */
    var shareDir: File? = null

    private val main = Handler(Looper.getMainLooper())
    private val graceLock = Runnable { lock() }

    /** When Dobr last launched something outside itself, or 0. */
    private var externalAt = 0L
    /** When Dobr went to the background during that outside flow, or 0. */
    private var stoppedAt = 0L

    fun unlock(vault: OpenVault, items: List<VaultItem>) {
        _items.value = items
        _open.value = vault
    }

    fun setItems(items: List<VaultItem>) {
        _items.value = items
    }

    fun lock() {
        main.removeCallbacks(graceLock)
        _open.value?.encKey?.fill(0)
        _open.value = null
        _items.value = emptyList()
        thumbs.evictAll()
        shareDir?.listFiles()?.forEach { it.delete() }
    }

    /** Call right before launching the photo picker, a file picker, billing or "Open with". */
    fun expectExternal() {
        externalAt = SystemClock.elapsedRealtime()
    }

    /** Dobr's own screen is in front again, so whatever it launched has finished. */
    fun onUiResumed() {
        externalAt = 0L
    }

    fun onAppStopped() {
        val now = SystemClock.elapsedRealtime()
        val launchedJustNow = externalAt > 0 && now - externalAt < EXTERNAL_START_WINDOW_MS
        externalAt = 0L
        if (launchedJustNow && _open.value != null) {
            stoppedAt = now
            main.removeCallbacks(graceLock)
            main.postDelayed(graceLock, EXTERNAL_GRACE_MS)
        } else {
            lock()
        }
    }

    fun onAppStarted() {
        main.removeCallbacks(graceLock)
        if (stoppedAt > 0 && SystemClock.elapsedRealtime() - stoppedAt > EXTERNAL_GRACE_MS) lock()
        stoppedAt = 0L
    }

    fun onScreenOff() {
        externalAt = 0L
        stoppedAt = 0L
        lock()
    }

    /** How long a picker or purchase sheet Dobr opened may keep the vault open in the background. */
    private const val EXTERNAL_GRACE_MS = 2 * 60 * 1000L
    /** Dobr has to leave the screen within this long of launching something for it to count. */
    private const val EXTERNAL_START_WINDOW_MS = 15 * 1000L
}
