package app.localgatekeys.android.sync;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.DocumentsContract;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Test setup for {@link TestDocumentsProvider} (same process and uid, so its grants are the provider's own): {@code reset}
 * makes an empty tree folder and returns its tree URI; {@code grant} / {@code revoke} give the calling app (or take back
 * from it) read and write access to a tree, persistable like the system picker's; {@code rename} sets the rename mode;
 * {@code nullNames} makes a renamed document's own query answer no display name;
 * {@code put} / {@code get} / {@code names} write and read the raw files, so tests check what is really stored without
 * going through the code under test; {@code created} lists every name the provider created.
 */
public final class TestDocumentsControl extends ContentProvider {
    /** The tree URI of {@code folder} under the test tree's root. */
    public static Uri tree(Context testContext, String folder) {
        return DocumentsContract.buildTreeDocumentUri(testContext.getPackageName() + ".documents", "r/" + folder);
    }

    @Override public boolean onCreate() {
        return true;
    }

    @Override public Bundle call(String method, String arg, Bundle extras) {
        Context ctx = getContext();
        File docs = TestDocumentsProvider.docsDir(ctx);
        Bundle out = new Bundle();
        try {
            switch (method) {
                case "reset":
                    TestDocumentsProvider.deleteAll(docs);
                    new File(docs, "r/" + arg).mkdirs();
                    TestDocumentsProvider.renameMode = TestDocumentsProvider.RenameMode.UNIQUIFY;
                    TestDocumentsProvider.created.clear();
                    TestDocumentsProvider.renamed.clear();
                    TestDocumentsProvider.nullNameAfterRename = false;
                    out.putString("tree", tree(ctx, arg).toString());
                    break;
                case "grant":
                    ctx.grantUriPermission(getCallingPackage(), Uri.parse(arg),
                        Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                            | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
                    break;
                case "revoke":
                    ctx.revokeUriPermission(Uri.parse(arg),
                        Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
                    break;
                case "nullNames":
                    TestDocumentsProvider.nullNameAfterRename = Boolean.parseBoolean(arg);
                    break;
                case "rename":
                    TestDocumentsProvider.renameMode = TestDocumentsProvider.RenameMode.valueOf(arg);
                    break;
                case "put": {
                    File f = new File(docs, "r/" + arg);
                    f.getParentFile().mkdirs();
                    try (FileOutputStream o = new FileOutputStream(f)) {
                        o.write(extras.getByteArray("data"));
                    }
                    break;
                }
                case "get": {
                    File f = new File(docs, "r/" + arg);
                    if (f.isFile()) {
                        byte[] b = new byte[(int) f.length()];
                        try (FileInputStream i = new FileInputStream(f)) {
                            int off = 0;
                            while (off < b.length) {
                                int n = i.read(b, off, b.length - off);
                                if (n < 0) break;
                                off += n;
                            }
                        }
                        out.putByteArray("data", b);
                    }
                    break;
                }
                case "names": {
                    String[] names = new File(docs, "r/" + arg).list();
                    if (names == null) names = new String[0];
                    Arrays.sort(names);
                    out.putStringArrayList("names", new ArrayList<>(Arrays.asList(names)));
                    break;
                }
                case "created":
                    synchronized (TestDocumentsProvider.created) {
                        out.putStringArrayList("names", new ArrayList<>(TestDocumentsProvider.created));
                    }
                    break;
                default:
                    throw new IllegalArgumentException(method);
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    @Override public Cursor query(Uri uri, String[] p, String s, String[] a, String o) {
        return null;
    }

    @Override public String getType(Uri uri) {
        return null;
    }

    @Override public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override public int delete(Uri uri, String s, String[] a) {
        return 0;
    }

    @Override public int update(Uri uri, ContentValues values, String s, String[] a) {
        return 0;
    }
}
