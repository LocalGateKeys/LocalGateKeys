using System.Diagnostics;
using System.Security.Cryptography;

namespace LocalGateKeys.PasskeyProvider.Provider;

/// <summary>
/// Refuses a replay of a request signature already accepted by this process. ECDSA and PSS signatures are
/// randomized, so Windows never produces the same bytes twice for two genuine requests. The key is the signature in
/// canonical form (<see cref="Canonical"/>): an ECDSA signature (r, s) and its malleated twin (r, n - s) both
/// verify, so both map to the low-s form (n of the curve the signature length names: P-256, P-384 or P-521) and a
/// twin counts as a replay. The request bytes are deliberately not the
/// key: a page that retries with the same options (same challenge) after the user closed the Windows dialog sends the
/// same encoded request with a fresh signature, and must work. Short-lived and bounded: entries expire after
/// <see cref="DefaultLifetime"/>, and at most <see cref="DefaultCapacity"/> are kept (oldest dropped first). Only
/// SHA-256 digests are held.
/// </summary>
public sealed class ReplayCache
{
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(10);
    public const int DefaultCapacity = 1024;

    private readonly Func<TimeSpan> _clock;
    private readonly TimeSpan _lifetime;
    private readonly int _capacity;
    private readonly Dictionary<string, TimeSpan> _seen = new(StringComparer.Ordinal);
    private readonly Queue<(string Digest, TimeSpan At)> _order = new();
    private readonly object _gate = new();

    public ReplayCache(Func<TimeSpan>? clock = null, TimeSpan? lifetime = null, int capacity = DefaultCapacity)
    {
        _clock = clock ?? Clock.Monotonic();
        _lifetime = lifetime ?? DefaultLifetime;
        _capacity = capacity;
    }

    /// <summary>
    /// An ECDSA r||s of 64, 96 or 132 bytes (P-256, P-384, P-521: the only accepted signatures of those lengths, RSA
    /// keys being 2048 bits or more) with s replaced by min(s, n - s); anything else unchanged.
    /// </summary>
    public static byte[] Canonical(ReadOnlySpan<byte> signature)
    {
        var copy = signature.ToArray();
        if (RequestSignature.EcdsaOrder(copy.Length) is not { } order)
            return copy;
        var half = copy.Length / 2;
        var s = new System.Numerics.BigInteger(copy.AsSpan(half, half), isUnsigned: true, isBigEndian: true);
        var low = order - s;
        if (s.IsZero || low.Sign <= 0 || low >= s)
            return copy;
        Array.Clear(copy, half, half);
        var bytes = low.ToByteArray(isUnsigned: true, isBigEndian: true);
        bytes.CopyTo(copy, copy.Length - bytes.Length);
        return copy;
    }

    /// <summary>True the first time a signature (canonical form) is offered; false for a replay within the lifetime.</summary>
    public bool TryAccept(ReadOnlySpan<byte> signature)
    {
        var digest = Convert.ToHexString(SHA256.HashData(Canonical(signature)));
        lock (_gate)
        {
            var now = _clock();
            while (_order.Count > 0 && (now - _order.Peek().At >= _lifetime || _order.Count >= _capacity))
            {
                var (old, at) = _order.Dequeue();
                if (_seen.TryGetValue(old, out var stored) && stored == at)
                    _seen.Remove(old);
            }
            if (_seen.ContainsKey(digest))
                return false;
            _seen[digest] = now;
            _order.Enqueue((digest, now));
            return true;
        }
    }
}

/// <summary>
/// A <c>CancelOperation</c> that arrives before its transaction is registered (while the signing key is fetched)
/// is remembered briefly, unverified, and checked against the request once the transaction registers. Bounded.
/// </summary>
public sealed class PendingCancels
{
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromSeconds(30);
    public const int Capacity = 64;

    private readonly Func<TimeSpan> _clock;
    private readonly TimeSpan _lifetime;
    private readonly Dictionary<Guid, (byte[] Signature, TimeSpan At)> _pending = [];
    private readonly object _gate = new();

    public PendingCancels(Func<TimeSpan>? clock = null, TimeSpan? lifetime = null)
    {
        _clock = clock ?? Clock.Monotonic();
        _lifetime = lifetime ?? DefaultLifetime;
    }

    public void Remember(Guid transactionId, byte[] signature)
    {
        lock (_gate)
        {
            Expire();
            if (_pending.Count >= Capacity && !_pending.ContainsKey(transactionId))
                _pending.Remove(_pending.MinBy(p => p.Value.At).Key);
            _pending[transactionId] = (signature, _clock());
        }
    }

    /// <summary>The remembered cancel signatures for this id, removed from the list.</summary>
    public byte[]? Take(Guid transactionId)
    {
        lock (_gate)
        {
            Expire();
            return _pending.Remove(transactionId, out var entry) ? entry.Signature : null;
        }
    }

    private void Expire()
    {
        var now = _clock();
        foreach (var id in _pending.Where(p => now - p.Value.At >= _lifetime).Select(p => p.Key).ToArray())
            _pending.Remove(id);
    }
}

internal static class Clock
{
    public static Func<TimeSpan> Monotonic()
    {
        var watch = Stopwatch.StartNew();
        return () => watch.Elapsed;
    }
}
