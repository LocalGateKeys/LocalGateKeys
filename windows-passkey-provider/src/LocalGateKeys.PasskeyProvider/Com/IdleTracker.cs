using System.Diagnostics;

namespace LocalGateKeys.PasskeyProvider.Com;

/// <summary>
/// Counts running COM calls and <c>IClassFactory::LockServer</c> locks. The server may exit only when no call runs,
/// no lock is held, no outside COM reference to the provider object is left, and nothing happened for
/// <see cref="DefaultIdle"/>.
/// </summary>
public sealed class IdleTracker
{
    public static readonly TimeSpan DefaultIdle = TimeSpan.FromSeconds(60);

    /// <summary>
    /// A <c>LockServer(TRUE)</c> whose client died is never released, so locks stop counting after this long with no
    /// call or lock change: a dead client cannot keep the process alive forever.
    /// </summary>
    public static readonly TimeSpan MaxLockedIdle = TimeSpan.FromMinutes(10);

    private readonly Func<TimeSpan> _clock;
    private readonly object _gate = new();
    private int _active;
    private int _locks;
    private TimeSpan _last;

    public IdleTracker(Func<TimeSpan>? clock = null)
    {
        if (clock is null)
        {
            var watch = Stopwatch.StartNew();
            clock = () => watch.Elapsed;
        }
        _clock = clock;
        _last = _clock();
    }

    public IDisposable Begin()
    {
        lock (_gate)
        {
            _active++;
            _last = _clock();
        }
        return new Scope(this);
    }

    public void Touch()
    {
        lock (_gate)
            _last = _clock();
    }

    /// <summary>LockServer(TRUE) adds a lock, LockServer(FALSE) removes one (never below zero).</summary>
    public void LockServer(bool locked)
    {
        lock (_gate)
        {
            _locks = locked ? _locks + 1 : Math.Max(0, _locks - 1);
            _last = _clock();
        }
    }

    public bool IsIdle(TimeSpan idle, int outsideReferences = 0)
    {
        lock (_gate)
            return _active == 0 && outsideReferences <= 0 && _clock() - _last >= idle && LocksExpired();
    }

    /// <summary>No call running and no lock held (time not considered): safe to end after revoking.</summary>
    public bool IsQuiet(int outsideReferences)
    {
        lock (_gate)
            return _active == 0 && outsideReferences <= 0 && LocksExpired();
    }

    // Caller holds _gate.
    private bool LocksExpired() => _locks == 0 || _clock() - _last >= MaxLockedIdle;

    private void End()
    {
        lock (_gate)
        {
            _active--;
            _last = _clock();
        }
    }

    private sealed class Scope(IdleTracker owner) : IDisposable
    {
        private int _done;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _done, 1) == 0)
                owner.End();
        }
    }
}
