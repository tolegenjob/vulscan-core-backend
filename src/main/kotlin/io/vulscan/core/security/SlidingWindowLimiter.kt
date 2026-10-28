package io.vulscan.core.security

import java.util.concurrent.ConcurrentHashMap

/** Ограничитель «не более [max] событий за [windowMs]» на ключ. Хранит данные в памяти процесса. */
class SlidingWindowLimiter(
    private val max: Int,
    private val windowMs: Long,
    private val now: () -> Long = System::currentTimeMillis,
) {
    private val events = ConcurrentHashMap<String, ArrayDeque<Long>>()

    /** @return 0, если событие разрешено и учтено; иначе число секунд до освобождения. */
    fun tryAcquire(key: String): Long {
        val time = now()
        val queue = events.computeIfAbsent(key) { ArrayDeque() }
        synchronized(queue) {
            while (queue.isNotEmpty() && time - queue.first() >= windowMs) queue.removeFirst()
            if (queue.size >= max) {
                val waitMs = windowMs - (time - queue.first())
                return ((waitMs + 999) / 1000).coerceAtLeast(1)
            }
            queue.addLast(time)
            return 0
        }
    }

    /** Сколько секунд ждать, если лимит по [key] исчерпан (0 — можно продолжать). Событие не учитывается. */
    fun retryAfterSec(key: String): Long {
        val time = now()
        val queue = events[key] ?: return 0
        synchronized(queue) {
            while (queue.isNotEmpty() && time - queue.first() >= windowMs) queue.removeFirst()
            if (queue.size < max) return 0
            return ((windowMs - (time - queue.first()) + 999) / 1000).coerceAtLeast(1)
        }
    }

    /** Учитывает событие без проверки лимита. */
    fun record(key: String) {
        val queue = events.computeIfAbsent(key) { ArrayDeque() }
        synchronized(queue) { queue.addLast(now()) }
    }

    /** Удаляет ключи без свежих событий (вызывается периодически, чтобы карта не росла). */
    fun evictIdle() {
        val time = now()
        events.entries.removeIf { (_, q) -> synchronized(q) { q.isEmpty() || time - q.last() >= windowMs } }
    }
}
