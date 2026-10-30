package app.localgatekeys.android.autofill

import android.app.assist.AssistStructure
import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.SigningInfo
import android.view.View
import android.view.autofill.AutofillId
import java.security.MessageDigest

/** `AssistStructure` to [FillNode]s (traversal order) for [FormParser]; and the typed text of a node on save. */
object StructureReader {
    fun nodes(structure: AssistStructure): List<FillNode<AutofillId>> {
        val out = ArrayList<FillNode<AutofillId>>()
        for (w in 0 until structure.windowNodeCount) walk(structure.getWindowNodeAt(w).rootViewNode, out)
        return out
    }

    private fun walk(n: AssistStructure.ViewNode, out: MutableList<FillNode<AutofillId>>) {
        val html = n.htmlInfo
        val attrs = HashMap<String, String>()
        html?.attributes?.forEach { p -> if (p.first != null && p.second != null) attrs[p.first.lowercase()] = p.second }
        val isInput = html?.tag?.equals("input", ignoreCase = true) == true
        val editable = n.autofillType == View.AUTOFILL_TYPE_TEXT &&
            (isInput || n.className?.contains("EditText") == true || n.className?.contains("TextInput") == true)
        out.add(
            FillNode(
                id = n.autofillId,
                hints = n.autofillHints?.toList() ?: emptyList(),
                inputType = n.inputType,
                idEntry = n.idEntry,
                hint = n.hint,
                html = if (isInput) attrs else emptyMap(),
                isEditable = editable,
                webDomain = n.webDomain,
                webScheme = n.webScheme,
                focused = n.isFocused,
            ),
        )
        for (c in 0 until n.childCount) walk(n.getChildAt(c), out)
    }

    /** The text typed into [id] (save requests only). */
    fun text(structure: AssistStructure, id: AutofillId): String? {
        fun find(n: AssistStructure.ViewNode): String? {
            if (n.autofillId == id) return n.autofillValue?.takeIf { it.isText }?.textValue?.toString()
            for (c in 0 until n.childCount) find(n.getChildAt(c))?.let { return it }
            return null
        }
        for (w in 0 until structure.windowNodeCount) find(structure.getWindowNodeAt(w).rootViewNode)?.let { return it }
        return null
    }
}

/** SHA-256 of an app's signing certificates (the current signers, or the lineage's latest). */
object Signatures {
    fun sha256(info: SigningInfo?): List<ByteArray> {
        info ?: return emptyList()
        val sigs = if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory
        val md = { b: ByteArray -> MessageDigest.getInstance("SHA-256").digest(b) }
        val list = sigs?.map { md(it.toByteArray()) } ?: emptyList()
        // With rotation the history is oldest first: the current certificate leads.
        return if (info.hasMultipleSigners()) list else list.reversed()
    }

    fun of(context: Context, packageName: String): List<ByteArray> = try {
        sha256(context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo)
    } catch (e: PackageManager.NameNotFoundException) {
        emptyList()
    }
}
