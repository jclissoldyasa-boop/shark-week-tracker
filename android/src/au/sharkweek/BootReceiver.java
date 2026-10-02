package au.sharkweek;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Alarms are cleared by a reboot or app update; set the next reminder and the daily update check again. */
public class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context c, Intent i) { Reminder.schedule(c); UpdateCheck.schedule(c); }
}
