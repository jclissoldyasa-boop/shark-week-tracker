package au.sharkweek;

import android.Manifest;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ContentValues;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.view.WindowManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Hosts the Shark Week page and gives it the SharkNative bridge.
 * The page is bundled in the APK but shown under the real site address, so it opens instantly and offline,
 * talks to the API as the same site, and password managers share saved logins between app and website.
 */
public class MainActivity extends Activity {
    static final String HOST = Site.HOST;
    static final String HOME = "https://" + HOST + "/app";
    private WebView web;
    private boolean loaded;

    @Override protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        // Privacy screen on by default (until the page says otherwise): no screenshots, blank in recent apps.
        setSecure(getSharedPreferences("sw", MODE_PRIVATE).getBoolean("secure", true));
        web = new WebView(this);
        web.setBackgroundColor(0xFF07162A);
        setContentView(web);

        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setGeolocationEnabled(false);
        s.setSaveFormData(false);
        s.setTextZoom(100);
        s.setUserAgentString(s.getUserAgentString() + " SharkWeekApp/" + version());
        WebView.setWebContentsDebuggingEnabled(false);
        web.addJavascriptInterface(new Bridge(), "SharkNative");
        web.setWebViewClient(new WebViewClient() {
            @Override public WebResourceResponse shouldInterceptRequest(WebView v, WebResourceRequest r) {
                Uri u = r.getUrl();
                if (!HOST.equals(u.getHost()) || !"GET".equals(r.getMethod())) return null;
                String path = u.getPath() == null ? "/" : u.getPath(), asset = null;
                if (path.equals("/app") || path.equals("/app.html") || path.equals("/")) asset = "index.html"; // the bundled app
                else if (path.equals("/privacy") || path.equals("/terms")) asset = path.substring(1) + ".html";
                if (asset == null) return null; // API calls and icons go to the network as normal
                try {
                    WebResourceResponse res = new WebResourceResponse("text/html", "utf-8", getAssets().open(asset));
                    res.setResponseHeaders(pageHeaders());
                    return res;
                } catch (java.io.IOException e) { return null; }
            }
            @Override public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest r) {
                Uri u = r.getUrl();
                if (HOST.equals(u.getHost()) && "https".equals(u.getScheme())) return false;
                try { startActivity(new Intent(Intent.ACTION_VIEW, u)); } catch (ActivityNotFoundException ignored) {}
                return true; // other sites (and tel: links) open outside the app
            }
            @Override public void onPageFinished(WebView v, String url) { loaded = true; }
        });
        if (saved != null) web.restoreState(saved); else web.loadUrl(HOME);
    }

    @Override protected void onResume() {
        super.onResume();
        if (loaded) web.evaluateJavascript("window.swResume&&window.swResume()", null);
    }

    @Override protected void onSaveInstanceState(Bundle out) { super.onSaveInstanceState(out); web.saveState(out); }

    @SuppressWarnings("deprecation")
    @Override public void onBackPressed() {
        web.evaluateJavascript("(window.swBack&&window.swBack())?'y':'n'", r -> {
            if ("\"y\"".equals(r)) return;
            if (web.canGoBack()) web.goBack(); else super.onBackPressed();
        });
    }

    private void setSecure(boolean on) {
        if (on) getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        else getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
        if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(!on);
    }

    private String version() {
        try { return getPackageManager().getPackageInfo(getPackageName(), 0).versionName; } catch (Exception e) { return "?"; }
    }

    private Map<String, String> pageHeaders() {
        Map<String, String> h = new HashMap<>();
        try (InputStream in = getAssets().open("csp.txt")) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            for (int n; (n = in.read(buf)) > 0; ) out.write(buf, 0, n);
            h.put("Content-Security-Policy", out.toString("UTF-8").trim());
        } catch (java.io.IOException ignored) {}
        h.put("X-Content-Type-Options", "nosniff");
        h.put("Referrer-Policy", "no-referrer");
        h.put("Cache-Control", "no-store");
        return h;
    }

    /** What the page can ask of the phone. Only the bundled page (on HOST) is ever loaded in this WebView. */
    private class Bridge {
        @JavascriptInterface public void setSecure(boolean on) {
            getSharedPreferences("sw", MODE_PRIVATE).edit().putBoolean("secure", on).apply();
            runOnUiThread(() -> MainActivity.this.setSecure(on));
        }
        /** [{"at": epochMs, "title", "text"}] — replaces all scheduled reminders. */
        @JavascriptInterface public void setReminders(String json) { Reminder.configure(MainActivity.this, json); }
        @JavascriptInterface public void askNotifications() {
            if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
                runOnUiThread(() -> requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1));
        }
        @JavascriptInterface public String version() { return MainActivity.this.version(); }
        @JavascriptInterface public String versionCode() {
            try { return String.valueOf(getPackageManager().getPackageInfo(getPackageName(), 0).getLongVersionCode()); } catch (Exception e) { return "0"; }
        }
        /** Opens an update download in the browser. Only our own site or our GitHub releases. */
        @JavascriptInterface public void openUrl(String url) {
            Uri u = Uri.parse(url);
            boolean ok = "https".equals(u.getScheme()) && (HOST.equals(u.getHost()) || "github.com".equals(u.getHost()));
            if (!ok) return;
            runOnUiThread(() -> { try { startActivity(new Intent(Intent.ACTION_VIEW, u)); } catch (ActivityNotFoundException ignored) {} });
        }
        /** Saves an export to Downloads. Returns a message for the page to show. */
        @JavascriptInterface public String saveFile(String name, String text, String mime) {
            try {
                ContentValues v = new ContentValues();
                v.put(MediaStore.Downloads.DISPLAY_NAME, name.replaceAll("[^A-Za-z0-9._-]", "_"));
                v.put(MediaStore.Downloads.MIME_TYPE, mime);
                v.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);
                Uri uri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, v);
                try (OutputStream out = getContentResolver().openOutputStream(uri)) { out.write(text.getBytes(StandardCharsets.UTF_8)); }
                return "Saved to Downloads: " + name;
            } catch (Exception e) { return "Couldn't save the file: " + e.getMessage(); }
        }
    }
}
