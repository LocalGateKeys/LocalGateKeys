using System.Globalization;
using System.Text;

namespace LocalGateKeys.PasskeyProvider.Diagnostics;

/// <summary>
/// One line per COM operation, for diagnosing a device run. Reason codes only (SECURITY.md, "Passkey provider
/// log"): the operation name, the first 8 hex digits of Windows' transaction id, an outcome word, HRESULTs, the
/// check that failed and the pipe stage, and the elapsed time. Never request bytes, RP IDs, user names or handles,
/// credential IDs, keys, signatures, tokens, paths or window titles: every text field is a fixed word, and
/// <see cref="Word"/> replaces anything else with <c>invalid</c>.
/// </summary>
public sealed record OperationRecord(
    string Operation, Guid TransactionId, string Outcome, int HResult, string? Check = null, string? Stage = null,
    string? Detail = null, int? ApiHResult = null, long ElapsedMs = 0);

public interface IProviderLog
{
    void Write(OperationRecord record);
}

/// <summary>Writes to <c>%LOCALAPPDATA%\LocalGateKeys\logs\passkey-provider.log</c>; moves it to <c>.1</c> past 256 KB.</summary>
public sealed class ProviderLog : IProviderLog
{
    public const long MaxBytes = 256 * 1024;
    public const int MaxWordLength = 48;
    private readonly string _path;
    private readonly Func<DateTimeOffset> _clock;
    private readonly object _gate = new();

    public ProviderLog(string path, Func<DateTimeOffset>? clock = null)
    {
        _path = path;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    public static string DefaultPath() =>
        Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LocalGateKeys", "logs",
                     "passkey-provider.log");

    private static readonly Lazy<ProviderLog> SharedInstance = new(() => new ProviderLog(DefaultPath()));

    public static ProviderLog Shared => SharedInstance.Value;

    /// <summary>Best effort: a log failure never changes an operation's result.</summary>
    public void Write(OperationRecord record)
    {
        try
        {
            var line = Line(record, _clock());
            lock (_gate)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                var info = new FileInfo(_path);
                if (info.Exists && info.Length >= MaxBytes)
                    File.Move(_path, _path + ".1", overwrite: true);
                File.AppendAllText(_path, line + "\n", Encoding.ASCII);
            }
        }
        catch (Exception)
        {
            // Never throws.
        }
    }

    public static string Line(OperationRecord record, DateTimeOffset now)
    {
        var line = new StringBuilder();
        line.Append(now.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture));
        line.Append(" op=").Append(Word(record.Operation));
        line.Append(" txn=").Append(record.TransactionId.ToString("N")[..8]);
        line.Append(" outcome=").Append(Word(record.Outcome));
        line.Append(" hr=").Append(Hex(record.HResult));
        if (record.Check is not null)
            line.Append(" check=").Append(Word(record.Check));
        if (record.Stage is not null)
            line.Append(" stage=").Append(Word(record.Stage));
        if (record.Detail is not null)
            line.Append(" detail=").Append(Word(record.Detail));
        if (record.ApiHResult is { } api)
            line.Append(" api_hr=").Append(Hex(api));
        line.Append(" ms=").Append(record.ElapsedMs.ToString(CultureInfo.InvariantCulture));
        return line.ToString();
    }

    /// <summary>An exception's type as a fixed word (<c>invalidoperationexception</c>); never its message.</summary>
    public static string TypeWord(Exception ex) => Word(ex.GetType().Name.ToLowerInvariant());

    public static string Hex(int hr) => "0x" + hr.ToString("X8", CultureInfo.InvariantCulture);

    /// <summary>A fixed reason word: lower-case letters, digits and <c>_</c>, at most 48; anything else is <c>invalid</c>.</summary>
    public static string Word(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return "none";
        if (value.Length > MaxWordLength)
            return "invalid";
        foreach (var c in value)
        {
            if (c is not ((>= 'a' and <= 'z') or (>= '0' and <= '9') or '_'))
                return "invalid";
        }
        return value;
    }
}

/// <summary>For tests and tools that want no log.</summary>
public sealed class NullProviderLog : IProviderLog
{
    public static NullProviderLog Instance { get; } = new();
    public void Write(OperationRecord record) { }
}
