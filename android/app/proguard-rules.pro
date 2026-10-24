# argon2kt loads its native library through JNI.
-keep class com.lambdapioneer.argon2kt.** { *; }

# Ruling 23: Play Billing's own telemetry (datatransport/CCT) is excluded from the build; billing guards its logger and
# skips logging when the classes are missing. These are the only classes R8 reported missing.
-dontwarn com.google.android.datatransport.**
