package au.sharkweek;

import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Calendar;

/**
 * Once a day, even when the app isn't open, asks the site whether a newer APK has been published
 * (/version.json) and, if so, posts one notification that downloads it. Android then asks the person
 * to install it; sideloaded apps can't update themselves silently. Sends nothing about the person.
 */
public class UpdateCheck extends BroadcastReceiver {
    static void schedule(Context c) {
        AlarmManager am = c.getSystemService(AlarmManager.class);
        Calendar t = Calendar.getInstance();
        t.set(Calendar.HOUR_OF_DAY, 10); t.set(Calendar.MINUTE, 30); t.set(Calendar.SECOND, 0);
        if (t.getTimeInMillis() <= System.currentTimeMillis()) t.add(Calendar.DAY_OF_YEAR, 1);
        am.setInexactRepeating(AlarmManager.RTC, t.getTimeInMillis(), AlarmManager.INTERVAL_DAY, pending(c));
    }

    private static PendingIntent pending(Context c) {
        return PendingIntent.getBroadcast(c, 7, new Intent(c, UpdateCheck.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    @Override public void onReceive(Context c, Intent i) {
        PendingResult done = goAsync();
        new Thread(() -> {
            try { check(c); } catch (Exception ignored) {} finally { done.finish(); }
        }).start();
    }

    private static void check(Context c) throws Exception {
        HttpURLConnection h = (HttpURLConnection) new URL("https://" + Site.HOST + "/version.json").openConnection();
        h.setConnectTimeout(15000); h.setReadTimeout(15000); h.setUseCaches(false);
        if (h.getResponseCode() != 200) return;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InputStream in = h.getInputStream()) { byte[] b = new byte[4096]; for (int n; (n = in.read(b)) > 0; ) out.write(b, 0, n); }
        JSONObject a = new JSONObject(out.toString("UTF-8")).optJSONObject("android");
        if (a == null) return;
        long latest = a.optLong("code"), mine = c.getPackageManager().getPackageInfo(c.getPackageName(), 0).getLongVersionCode();
        android.content.SharedPreferences prefs = c.getSharedPreferences("sw", Context.MODE_PRIVATE);
        if (latest <= mine || prefs.getLong("updateNotified", 0) == latest) return; // up to date, or already told them about this one
        String url = "https://" + Site.HOST + a.optString("url", "/download/SharkWeek.apk");
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("updates", "App updates", NotificationManager.IMPORTANCE_DEFAULT));
        PendingIntent open = PendingIntent.getActivity(c, 8, new Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), PendingIntent.FLAG_IMMUTABLE);
        nm.notify(9001, new Notification.Builder(c, "updates").setSmallIcon(R.drawable.ic_note)
                .setContentTitle("Shark Week update available")
                .setContentText("Version " + a.optString("name") + " is ready. Tap to download, then tap the file to install.")
                .setStyle(new Notification.BigTextStyle().bigText("Version " + a.optString("name") + " is ready. " + a.optString("notes") + "\n\nTap to download, then open the file to install. Your data stays."))
                .setContentIntent(open).setAutoCancel(true).build());
        prefs.edit().putLong("updateNotified", latest).apply();
    }
}
