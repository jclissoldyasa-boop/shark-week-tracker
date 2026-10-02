package au.sharkweek;

import android.app.AppOpsManager;
import android.app.usage.UsageEvents;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.os.Process;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

/**
 * Estimates sleep from when the screen was on or off. Only screen on/off events are read:
 * never which apps were used. Everything is worked out on the phone; the page stores the result
 * (bedtime, wake time, minutes, times woken) in the person's encrypted log.
 *
 * For each morning, the longest screen-off stretch between 6 pm the evening before and 2 pm is the
 * likely sleep. Quick screen checks shorter than BRIEF (looking at the time) don't end it; they're
 * counted as times woken. Stretches under MIN_SLEEP aren't reported.
 */
final class Sleep {
    private static final long MIN = 60_000L, BRIEF = 6 * MIN, MIN_SLEEP = 3 * 60 * MIN;

    static boolean allowed(Context c) {
        AppOpsManager ops = c.getSystemService(AppOpsManager.class);
        return ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), c.getPackageName()) == AppOpsManager.MODE_ALLOWED;
    }

    /** Last `days` mornings, as [{"date":"YYYY-MM-DD","bed":ms,"wake":ms,"min":n,"wakes":n}]. */
    static String nights(Context c, int days) {
        JSONArray out = new JSONArray();
        if (!allowed(c)) return out.toString();
        long now = System.currentTimeMillis();
        Calendar first = Calendar.getInstance();
        first.add(Calendar.DAY_OF_YEAR, -days);
        first.set(Calendar.HOUR_OF_DAY, 18); first.set(Calendar.MINUTE, 0); first.set(Calendar.SECOND, 0); first.set(Calendar.MILLISECOND, 0);

        // Screen-off periods: [off, on]
        List<long[]> off = new ArrayList<>();
        UsageEvents ev = c.getSystemService(UsageStatsManager.class).queryEvents(first.getTimeInMillis() - 12 * 60 * MIN, now);
        UsageEvents.Event e = new UsageEvents.Event();
        long offAt = -1;
        while (ev.hasNextEvent()) {
            ev.getNextEvent(e);
            int t = e.getEventType();
            if (t == UsageEvents.Event.SCREEN_NON_INTERACTIVE) offAt = e.getTimeStamp();
            else if (t == UsageEvents.Event.SCREEN_INTERACTIVE && offAt > 0) { off.add(new long[]{offAt, e.getTimeStamp()}); offAt = -1; }
        }
        if (offAt > 0) off.add(new long[]{offAt, now}); // still off

        for (int d = days - 1; d >= 0; d--) {
            Calendar morning = Calendar.getInstance();
            morning.add(Calendar.DAY_OF_YEAR, -d);
            Calendar from = (Calendar) morning.clone(), to = (Calendar) morning.clone();
            from.add(Calendar.DAY_OF_YEAR, -1);
            from.set(Calendar.HOUR_OF_DAY, 18); from.set(Calendar.MINUTE, 0); from.set(Calendar.SECOND, 0); from.set(Calendar.MILLISECOND, 0);
            to.set(Calendar.HOUR_OF_DAY, 14); to.set(Calendar.MINUTE, 0); to.set(Calendar.SECOND, 0); to.set(Calendar.MILLISECOND, 0);
            long a = from.getTimeInMillis(), b = Math.min(to.getTimeInMillis(), now);
            if (b <= a) continue;

            long bestStart = 0, bestEnd = 0, bestOff = 0; int bestWakes = 0;
            long curStart = -1, curEnd = -1, curOff = 0; int curWakes = 0;
            for (long[] p : off) {
                long s = Math.max(p[0], a), en = Math.min(p[1], b);
                if (en <= s) continue;
                if (curStart >= 0 && s - curEnd <= BRIEF) { curEnd = en; curOff += en - s; curWakes++; }
                else { curStart = s; curEnd = en; curOff = en - s; curWakes = 0; }
                if (curOff > bestOff) { bestStart = curStart; bestEnd = curEnd; bestOff = curOff; bestWakes = curWakes; }
            }
            // Still asleep (screen off right up to now) this morning: not finished yet.
            if (bestOff < MIN_SLEEP || bestEnd >= now - MIN) continue;
            try {
                out.put(new JSONObject().put("date", String.format(java.util.Locale.ROOT, "%04d-%02d-%02d",
                        morning.get(Calendar.YEAR), morning.get(Calendar.MONTH) + 1, morning.get(Calendar.DAY_OF_MONTH)))
                        .put("bed", bestStart).put("wake", bestEnd).put("min", bestOff / MIN).put("wakes", bestWakes));
            } catch (Exception ignored) {}
        }
        return out.toString();
    }
}
