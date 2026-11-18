# Access rule vectors (contract section 4)

- `effective.json`: `effective(record, device_class, today)`.
- `preserve.json`: the full Python sync normal form is given; other cores compare `scope.access` of
  their own normal form with it by `canon` (other fields may differ by core).
- `stricter.json`: `stricter(a, b)`; `null` means absent. Non-default values are kept as written
  (an unknown value such as `"twice"` stays, because it reads as the strict one); unknown keys are
  kept; a value that is not an object wins as is.
