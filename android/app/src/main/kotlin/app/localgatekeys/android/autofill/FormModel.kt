package app.localgatekeys.android.autofill

/**
 * One view node of an `AssistStructure`, reduced to what field detection needs. [id] is the node's `AutofillId` on
 * the device and any token in tests. Built by `StructureReader` (Android) so [FormParser] stays pure.
 */
data class FillNode<T>(
    val id: T?,
    val hints: List<String> = emptyList(),
    val inputType: Int = 0,
    val idEntry: String? = null,
    val hint: String? = null,
    /** HTML `input` attributes from a browser or WebView (`type`, `name`, `id`, `autocomplete`, ...). */
    val html: Map<String, String> = emptyMap(),
    val isEditable: Boolean = false,
    val webDomain: String? = null,
    val webScheme: String? = null,
    val focused: Boolean = false,
)

/** The login fields found in one request. No values: the service never reads what the person typed except on save. */
data class ParsedForm<T>(
    val usernames: List<T>,
    val passwords: List<T>,
    /** A sign-up or change-password form (a `new-password` field). */
    val newPassword: Boolean,
    val webDomain: String?,
    val webScheme: String?,
) {
    val isEmpty: Boolean get() = usernames.isEmpty() && passwords.isEmpty()

    /** Ids and counts only. */
    override fun toString(): String =
        "ParsedForm(usernames=${usernames.size}, passwords=${passwords.size}, newPassword=$newPassword, web=${webDomain != null})"
}

/** Username and password field detection: hints first, then HTML attributes, input type, and id/hint words. */
object FormParser {
    enum class Role { USERNAME, PASSWORD, NEW_PASSWORD, OTHER, NONE }

    // android.text.InputType constants (inlined so this file runs in plain JVM tests).
    private const val CLASS_MASK = 0x0000000f
    private const val VARIATION_MASK = 0x00000ff0
    private const val CLASS_TEXT = 1
    private const val CLASS_NUMBER = 2
    private val TEXT_PASSWORDS = setOf(0x80, 0x90, 0xe0)
    private val TEXT_EMAILS = setOf(0x20, 0xd0)
    private const val NUMBER_PASSWORD = 0x10

    private val USER_HINTS = setOf("username", "emailaddress", "newusername", "email")
    private val PASSWORD_HINTS = setOf("password", "currentpassword", "current-password")
    private val NEW_PASSWORD_HINTS = setOf("newpassword", "new-password")
    private val OTHER_HINTS = setOf(
        "smsotpcode", "one-time-code", "creditcardnumber", "creditcardsecuritycode", "postaladdress", "phone",
        "phonenumber", "name", "postalcode", "search",
    )

    private val PASSWORD_WORDS = listOf(
        "password", "passwd", "passwort", "kennwort", "pwd", "pass", "motdepasse", "contrasena", "contraseña", "senha",
        "пароль", "parola", "wachtwoord", "haslo", "hasło",
    )
    private val USER_WORDS = listOf(
        "username", "user", "login", "email", "e-mail", "mail", "account", "identifier", "benutzer", "utilisateur",
        "usuario", "nomeutente", "gebruikersnaam", "logon", "signin",
    )
    private val NOT_LOGIN_WORDS = listOf("search", "otp", "captcha", "code", "query", "zip", "coupon", "promo")

    private fun norm(s: String?): String = (s ?: "").lowercase().replace("_", "").replace(" ", "").replace(".", "")

    private fun hasWord(text: String, words: List<String>): Boolean = words.any { text.contains(it) }

    /** The role of one node. NONE for a node that is not an editable field. */
    fun <T> role(n: FillNode<T>): Role {
        if (!n.isEditable && n.html["type"] == null) return Role.NONE
        for (h in n.hints.map { it.lowercase() }) {
            when (h) {
                in NEW_PASSWORD_HINTS -> return Role.NEW_PASSWORD
                in PASSWORD_HINTS -> return Role.PASSWORD
                in USER_HINTS -> return Role.USERNAME
                in OTHER_HINTS -> return Role.OTHER
            }
        }
        val type = n.html["type"]?.lowercase()
        if (type != null && type !in setOf("text", "email", "password", "tel", "")) return Role.OTHER
        val auto = n.html["autocomplete"]?.lowercase()?.split(' ')?.filter { it.isNotEmpty() } ?: emptyList()
        when {
            "new-password" in auto -> return Role.NEW_PASSWORD
            "current-password" in auto -> return Role.PASSWORD
            "username" in auto || "email" in auto -> return Role.USERNAME
            "one-time-code" in auto -> return Role.OTHER
        }
        if (type == "password") return Role.PASSWORD
        if (type == "email") return Role.USERNAME
        val cls = n.inputType and CLASS_MASK
        val variation = n.inputType and VARIATION_MASK
        if (cls == CLASS_TEXT && variation in TEXT_PASSWORDS) return Role.PASSWORD
        if (cls == CLASS_NUMBER && variation == NUMBER_PASSWORD) return Role.PASSWORD
        if (cls == CLASS_TEXT && variation in TEXT_EMAILS) return Role.USERNAME
        val words = listOf(n.idEntry, n.hint, n.html["name"], n.html["id"], n.html["placeholder"]).joinToString("|") { norm(it) }
        if (hasWord(words, NOT_LOGIN_WORDS) && !hasWord(words, listOf("password", "passwort", "username"))) return Role.OTHER
        if (hasWord(words, PASSWORD_WORDS)) return Role.PASSWORD
        if (hasWord(words, USER_WORDS)) return Role.USERNAME
        return if (cls == CLASS_TEXT || type == "text" || type == "tel") Role.OTHER else Role.NONE
    }

    /**
     * The login fields of [nodes] (in traversal order). With a password field but no recognised username, the last
     * plain text field before the first password field is taken as the username (most login forms).
     */
    fun <T> parse(nodes: List<FillNode<T>>): ParsedForm<T> {
        val users = ArrayList<T>()
        val passwords = ArrayList<T>()
        var newPassword = false
        var lastText: T? = null
        var fallbackUser: T? = null
        var domain: String? = null
        var scheme: String? = null
        for (n in nodes) {
            if (domain == null && !n.webDomain.isNullOrBlank()) {
                domain = n.webDomain.trim().lowercase()
                scheme = n.webScheme?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
            }
            val id = n.id ?: continue
            when (role(n)) {
                Role.USERNAME -> users.add(id)
                Role.PASSWORD -> {
                    if (passwords.isEmpty() && fallbackUser == null) fallbackUser = lastText
                    passwords.add(id)
                }
                Role.NEW_PASSWORD -> {
                    if (passwords.isEmpty() && fallbackUser == null) fallbackUser = lastText
                    passwords.add(id)
                    newPassword = true
                }
                Role.OTHER -> lastText = id
                Role.NONE -> {}
            }
        }
        if (users.isEmpty() && passwords.isNotEmpty()) fallbackUser?.let { users.add(it) }
        return ParsedForm(users, passwords, newPassword, domain, scheme)
    }
}
