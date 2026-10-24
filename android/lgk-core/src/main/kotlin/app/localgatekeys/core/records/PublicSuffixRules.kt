package app.localgatekeys.core.records

/**
 * Public Suffix List rules in A-label form (desktop `SuffixRules`). Port of Swift `PublicSuffixRules`.
 * Rules are compared as strings; hosts are ASCII on the phone, so UTF-16 equality is code point equality.
 */
class PublicSuffixRules internal constructor(
    val normal: Set<String>,
    val wildcard: Set<String>,
    val exception: Set<String>,
) {
    companion object {
        /** The desktop's `_LOCAL_SUFFIX_RULES` (they only ever narrow a registrable domain). */
        val localRules: List<String> = listOf("*.web.core.windows.net")

        /**
         * `parse_suffix_rules` over the list text, plus [localRules]. Null when the list is truncated
         * (`<= 1000` normal rules), which makes `base_domain` fail closed like the desktop.
         */
        fun load(listText: String): PublicSuffixRules? {
            val r = parse(listText.split("\r\n", "\n", "\r"))
            val local = parse(localRules)
            val merged = PublicSuffixRules(r.normal + local.normal, r.wildcard + local.wildcard, r.exception + local.exception)
            return if (merged.normal.size > 1000) merged else null
        }

        /** `parse_suffix_rules`. */
        fun parse(lines: List<String>): PublicSuffixRules {
            val normal = HashSet<String>()
            val wildcard = HashSet<String>()
            val exception = HashSet<String>()
            for (raw in lines) {
                val line = PyStrip.strip(raw)
                if (line.isEmpty() || line.startsWith("//")) continue
                var rule = PyStrip.split(line)[0]
                var target = 0
                if (rule.startsWith("!")) {
                    target = 2
                    rule = rule.substring(1)
                } else if (rule.startsWith("*.")) {
                    target = 1
                    rule = rule.substring(2)
                }
                if (rule.isEmpty() || rule.contains('*') || rule.contains('!')) continue
                val ascii = ruleToAscii(rule) ?: continue
                when (target) {
                    1 -> wildcard.add(ascii)
                    2 -> exception.add(ascii)
                    else -> normal.add(ascii)
                }
            }
            return PublicSuffixRules(normal, wildcard, exception)
        }

        /** `_rule_to_ascii`: ASCII labels lower-cased, others IDNA-encoded (null = rule ignored). */
        private fun ruleToAscii(rule: String): String? {
            val out = StringBuilder()
            for ((i, label) in rule.split(".").withIndex()) {
                if (i > 0) out.append('.')
                if (label.all { it.code < 0x80 }) {
                    out.append(label.lowercase())
                } else {
                    out.append(Punycode.idnaLabel(label.codePoints().toArray()) ?: return null)
                }
            }
            return out.toString()
        }
    }

    /** `public_suffix` for an A-label host. */
    fun publicSuffix(host: String): String {
        val labels = host.split(".")
        val count = labels.size
        fun join(from: Int): String = labels.subList(from, count).joinToString(".")
        for (i in 0 until count) {
            if (join(i) in exception) return if (i + 1 < count) join(i + 1) else ""
        }
        for (i in 0 until count) {
            if (join(i) in normal) return join(i)
            if (i + 1 < count && join(i + 1) in wildcard) return join(i)
        }
        return labels[count - 1]
    }
}
