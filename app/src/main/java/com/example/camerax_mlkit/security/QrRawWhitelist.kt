package com.example.camerax_mlkit.security

import android.util.Log
import java.security.MessageDigest

object QrRawWhitelist {

    // raw QR 문자열을 SHA-256으로 해시해서 16진수 문자열로 반환
    private fun sha256(text: String): String {
        val bytes = text.trim().toByteArray(Charsets.UTF_8)
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(bytes)
        // 바이트 배열을 16진수 문자열로 변환 (소문자)
        return digest.joinToString("") { "%02x".format(it) }
    }

    // 🔒 LV2: raw 문자열 → 매장 locationId 매핑
    //  - 스캔된 raw를 키로 조회해서 이 QR이 어느 매장 소속인지 판별
    //  - A안: 키를 '원문 URL'이 아니라 'SHA-256 해시값'으로 사용
    private val map: MutableMap<String, String> = linkedMapOf(
        // ===== A 매장 (store_duksung_a) =====
        sha256("https://pay.naver.com/remit/qr/inflow?v=1&a=1002858310954&c=020&d=317bb0795ee5eb20e48760734b5d7372")
                to "store_duksung_a",
        sha256("https://qr.kakaopay.com/281006011000013813839564")
                to "store_duksung_a",

        // ===== B 매장 (store_duksung_b) =====
        sha256("https://pay.naver.com/remit/qr/inflow?v=1&a=110290521049&c=088&d=d268ef57c81cc46b34a51e96ff0497cb")
                to "store_duksung_b",
        sha256("https://qr.kakaopay.com/281006011000077232921124")
                to "store_duksung_b",
    )

    /** 조회: 이 raw가 어느 매장 소속인지 반환 (없으면 null)
     *   - 내부적으로는 raw 전체를 SHA-256으로 해시해서 비교
     */
    fun locationOf(raw: String): String? {
        val hash = sha256(raw)
        return map[hash]
    }

    /** 등록/갱신: 런타임에서 캡처한 raw를 특정 매장에 바인딩(시연 편의용)
     *   - 내부적으로 raw 전체를 SHA-256으로 해시해서 map에 저장
     */
    fun registerRawForStore(raw: String, locationId: String) {
        val hash = sha256(raw)
        map[hash] = locationId
    }

    /** (선택) 일괄 등록 */
    fun registerAll(pairs: List<Pair<String, String>>) {
        pairs.forEach { (raw, loc) -> registerRawForStore(raw, loc) }
    }

    // ✅ LV2 헬퍼 — 이 raw가 현재 컨텍스트 locationId에서 허용되는지
    fun isAllowedAt(raw: String, ctxLocationId: String?): Boolean {
        val ctx  = ctxLocationId?.trim()?.lowercase() ?: return false
        val qrId = locationOf(raw)?.trim()?.lowercase() ?: return false
        return qrId == ctx
    }

    // ✅ 디버그용: 해시 기반 검증이 제대로 동작하는지 로그로 확인
    fun debugLog(raw: String) {
        val hash = sha256(raw)
        val exists = map.containsKey(hash)

        Log.d(
            "HASH_DEBUG",
            """
            ===== QR 해시 검증 로그 =====
            [원문 Raw]
            $raw

            [SHA-256 Hash]
            $hash

            [화이트리스트 매칭 여부]
            ${if (exists) "✔ 등록된 해시입니다" else "✘ 화이트리스트에 없음"}

            =============================
            """.trimIndent()
        )
    }
}
