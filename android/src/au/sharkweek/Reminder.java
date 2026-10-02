package au.sharkweek;

import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Reminders worked out by the page (period coming up, fertile window, daily log, partner heads-up), as a
 * list of {"at", "title", "text", "act"?}. One alarm is set for the earliest; when it fires it shows every due
 * reminder and sets the next. The texts are already discreet if the person chose that.
 */
public class Reminder extends BroadcastReceiver {
    static void configure(Context c, String json) {
        c.getSharedPreferences("sw", Context.MODE_PRIVATE).edit().putString("reminders", json).apply();
        schedule(c);
    }

    static void schedule(Context c) {
        AlarmManager am = c.getSystemService(AlarmManager.class);
        PendingIntent pi = PendingIntent.getBroadcast(c, 0, new Intent(c, Reminder.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        am.cancel(pi);
        long next = Long.MAX_VALUE, now = System.currentTimeMillis();
        JSONArray a = list(c);
        for (int i = 0; i < a.length(); i++) { long at = a.optJSONObject(i).optLong("at"); if (at > now && at < next) next = at; }
        // A 10-minute window doesn't need the exact-alarm permission and still arrives on time.
        if (next != Long.MAX_VALUE) am.setWindow(AlarmManager.RTC_WAKEUP, next, 10 * 60 * 1000, pi);
    }

    @Override public void onReceive(Context c, Intent i) {
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("remind", "Reminders", NotificationManager.IMPORTANCE_DEFAULT));
        long now = System.currentTimeMillis();
        JSONArray a = list(c), keep = new JSONArray();
        for (int k = 0; k < a.length(); k++) {
            JSONObject r = a.optJSONObject(k);
            long at = r.optLong("at");
            if (at > now + 60_000) { keep.put(r); continue; }
            if (now - at > 6 * 3600_000L) continue; // missed by hours (phone was off): skip rather than nag late
            Intent openApp = new Intent(c, MainActivity.class).setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            String act = r.optString("act", "");
            if (!act.isEmpty()) openApp.putExtra("act", act); // e.g. "partner": opens the heads-up to send
            PendingIntent open = PendingIntent.getActivity(c, act.isEmpty() ? 0 : act.hashCode() & 0xFFFF, openApp, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
            Notification n = new Notification.Builder(c, "remind").setSmallIcon(R.drawable.ic_note)
                    .setContentTitle(r.optString("title", "Shark Week")).setContentText(r.optString("text", ""))
                    .setVisibility(Notification.VISIBILITY_PRIVATE)
                    .setContentIntent(open).setAutoCancel(true).build();
            nm.notify((int) (at / 60000 % 100000), n);
        }
        c.getSharedPreferences("sw", Context.MODE_PRIVATE).edit().putString("reminders", keep.toString()).apply();
        schedule(c);
    }

    private static JSONArray list(Context c) {
        try { return new JSONArray(c.getSharedPreferences("sw", Context.MODE_PRIVATE).getString("reminders", "[]")); } catch (Exception e) { return new JSONArray(); }
    }
}
