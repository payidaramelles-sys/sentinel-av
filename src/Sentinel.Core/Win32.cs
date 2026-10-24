using System.Runtime.InteropServices;

namespace Sentinel.Core;

public static class Win32
{
    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    public static TimeSpan IdleTime()
    {
        try
        {
            var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
            if (!GetLastInputInfo(ref info)) return TimeSpan.Zero;
            var idleMs = unchecked((uint)Environment.TickCount - info.dwTime);
            return TimeSpan.FromMilliseconds(idleMs);
        }
        catch
        {
            return TimeSpan.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS
    {
        public byte ACLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public uint BatteryLifeTime;
        public uint BatteryFullLifeTime;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS status);

    public static bool IsOnBattery()
    {
        try
        {
            if (!GetSystemPowerStatus(out var s)) return false;
            return s.ACLineStatus == 0;
        }
        catch
        {
            return false;
        }
    }

    public static void LowPriority(bool enabled)
    {
        try
        {
            var h = GetCurrentThread();
            SetThreadPriority(h, enabled ? -2 : 0); // THREAD_PRIORITY_BELOW_NORMAL = -1, LOWEST = -2
        }
        catch
        {
            // ignore
        }
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetThreadPriority(IntPtr hThread, int nPriority);
}
