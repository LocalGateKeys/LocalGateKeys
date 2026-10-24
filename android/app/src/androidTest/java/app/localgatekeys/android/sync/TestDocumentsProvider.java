package app.localgatekeys.android.sync;

import android.database.Cursor;
import android.database.MatrixCursor;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract.Document;
import android.provider.DocumentsContract.Root;
import android.provider.DocumentsProvider;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * A local document tree for the cloud-folder device tests, served from the TEST package's own files (never the app's,
 * never real cloud data). Document ids are paths under {@code docs/} ("r" is the root). Renames follow {@link #renameMode}:
 * UNIQUIFY as Android's own storage ({@code name (1)} when the name is taken), REPLACE (a provider that renames over an
 * existing file), UNSUPPORTED (no rename at all), DUPLICATE (a provider that keeps two documents under one name; on
 * disk the second is {@code name#dup1}, shown as {@code name}). With {@link #nullNameAfterRename}, a renamed document's
 * own query answers no display name (listing it still shows the name).
 *
 * <p>Java, not Kotlin: this runs in the test package's own process (its own uid, so the app reaches it only through a
 * real URI grant), and the test APK leaves the Kotlin runtime to the app APK.
 */
public final class TestDocumentsProvider extends DocumentsProvider {
    public enum RenameMode { UNIQUIFY, REPLACE, UNSUPPORTED, DUPLICATE }

    static volatile RenameMode renameMode = RenameMode.UNIQUIFY;
    /** Every name a create asked for and got (temp files included), in order. */
    static final List<String> created = Collections.synchronizedList(new ArrayList<>());
    static volatile boolean nullNameAfterRename = false;
    static final java.util.Set<String> renamed = Collections.synchronizedSet(new java.util.HashSet<>());

    private static final String[] ROOT_COLUMNS = {Root.COLUMN_ROOT_ID, Root.COLUMN_DOCUMENT_ID, Root.COLUMN_TITLE, Root.COLUMN_FLAGS};
    private static final String[] DOC_COLUMNS = {
        Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME, Document.COLUMN_MIME_TYPE, Document.COLUMN_SIZE,
        Document.COLUMN_LAST_MODIFIED, Document.COLUMN_FLAGS,
    };

    static File docsDir(android.content.Context context) {
        return new File(context.getFilesDir(), "docs");
    }

    /** Android storage's rule: {@code name (1).ext}, {@code name (2).ext}... when the name is taken. */
    static File unique(File dir, String name) {
        File f = new File(dir, name);
        if (!f.exists()) return f;
        int dot = name.lastIndexOf('.');
        String base = dot > 0 ? name.substring(0, dot) : name;
        String ext = dot > 0 ? name.substring(dot) : "";
        int n = 1;
        while (f.exists()) f = new File(dir, base + " (" + (n++) + ")" + ext);
        return f;
    }

    @Override public boolean onCreate() {
        return true;
    }

    @Override public Cursor queryRoots(String[] projection) {
        MatrixCursor c = new MatrixCursor(projection != null ? projection : ROOT_COLUMNS);
        c.newRow().add(Root.COLUMN_ROOT_ID, "root").add(Root.COLUMN_DOCUMENT_ID, "r").add(Root.COLUMN_TITLE, "LGK test tree")
            .add(Root.COLUMN_FLAGS, Root.FLAG_SUPPORTS_CREATE | Root.FLAG_SUPPORTS_IS_CHILD | Root.FLAG_LOCAL_ONLY);
        return c;
    }

    @Override public Cursor queryDocument(String documentId, String[] projection) throws FileNotFoundException {
        File f = file(documentId);
        if (!f.exists()) throw new FileNotFoundException(documentId);
        MatrixCursor c = new MatrixCursor(projection != null ? projection : DOC_COLUMNS);
        row(c, documentId, f, nullNameAfterRename && renamed.contains(documentId));
        return c;
    }

    @Override public Cursor queryChildDocuments(String parentDocumentId, String[] projection, String sortOrder)
            throws FileNotFoundException {
        File dir = file(parentDocumentId);
        if (!dir.isDirectory()) throw new FileNotFoundException(parentDocumentId);
        MatrixCursor c = new MatrixCursor(projection != null ? projection : DOC_COLUMNS);
        String[] names = dir.list();
        if (names != null) {
            Arrays.sort(names);
            for (String n : names) row(c, parentDocumentId + "/" + n, new File(dir, n), false);
        }
        return c;
    }

    @Override public ParcelFileDescriptor openDocument(String documentId, String mode, CancellationSignal signal)
            throws FileNotFoundException {
        File f = file(documentId);
        if (!f.isFile()) throw new FileNotFoundException(documentId);
        return ParcelFileDescriptor.open(f, ParcelFileDescriptor.parseMode(mode));
    }

    @Override public String createDocument(String parentDocumentId, String mimeType, String displayName)
            throws FileNotFoundException {
        File dir = file(parentDocumentId);
        if (!dir.isDirectory()) throw new FileNotFoundException(parentDocumentId);
        File f = unique(dir, displayName);
        boolean ok;
        try {
            ok = Document.MIME_TYPE_DIR.equals(mimeType) ? f.mkdir() : f.createNewFile();
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
        if (!ok) throw new IllegalStateException("could not create " + displayName);
        created.add(f.getName());
        return parentDocumentId + "/" + f.getName();
    }

    @Override public String renameDocument(String documentId, String displayName) throws FileNotFoundException {
        File f = file(documentId);
        if (!f.exists()) throw new FileNotFoundException(documentId);
        File target;
        switch (renameMode) {
            case UNSUPPORTED: throw new UnsupportedOperationException("Rename not supported");
            case UNIQUIFY: target = unique(f.getParentFile(), displayName); break;
            case DUPLICATE: {
                target = new File(f.getParentFile(), displayName);
                int n = 1;
                while (target.exists()) target = new File(f.getParentFile(), displayName + "#dup" + (n++));
                break;
            }
            default: target = new File(f.getParentFile(), displayName); break;
        }
        if (!f.renameTo(target)) throw new IllegalStateException("rename failed");
        String id = documentId.substring(0, documentId.lastIndexOf('/')) + "/" + target.getName();
        renamed.add(id);
        return id;
    }

    @Override public void deleteDocument(String documentId) throws FileNotFoundException {
        File f = file(documentId);
        if (!f.exists()) throw new FileNotFoundException(documentId);
        if (!deleteAll(f)) throw new IllegalStateException("delete failed");
    }

    @Override public boolean isChildDocument(String parentDocumentId, String documentId) {
        return documentId.startsWith(parentDocumentId + "/");
    }

    static boolean deleteAll(File f) {
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) deleteAll(k);
        return f.delete();
    }

    private File file(String id) {
        if (!(id.equals("r") || id.startsWith("r/"))) throw new IllegalArgumentException("bad id " + id);
        for (String p : id.split("/", -1)) {
            if (p.isEmpty() || p.equals(".") || p.equals("..")) throw new IllegalArgumentException("bad id " + id);
        }
        return new File(docsDir(getContext()), id);
    }

    private static void row(MatrixCursor c, String id, File f, boolean noName) {
        int flags = Document.FLAG_SUPPORTS_DELETE;
        if (renameMode != RenameMode.UNSUPPORTED) flags |= Document.FLAG_SUPPORTS_RENAME;
        flags |= f.isDirectory() ? Document.FLAG_DIR_SUPPORTS_CREATE : Document.FLAG_SUPPORTS_WRITE;
        String shown = f.getName();
        int dup = shown.indexOf("#dup");
        if (dup > 0) shown = shown.substring(0, dup);
        c.newRow().add(Document.COLUMN_DOCUMENT_ID, id)
            .add(Document.COLUMN_DISPLAY_NAME, noName ? null : id.equals("r") ? "LGK test tree" : shown)
            .add(Document.COLUMN_MIME_TYPE, f.isDirectory() ? Document.MIME_TYPE_DIR : "application/octet-stream")
            .add(Document.COLUMN_SIZE, f.length()).add(Document.COLUMN_LAST_MODIFIED, f.lastModified()).add(Document.COLUMN_FLAGS, flags);
    }
}
