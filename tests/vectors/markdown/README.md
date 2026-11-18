# Markdown subset vectors

`cases.json` is a list of `{name, input, nodes}`. Every platform parser (Python/web UI `webui/src/lib/markdown.js`,
Swift, Kotlin) must return exactly `nodes` for `input`. Display only: nothing here ever produces HTML, links are
never clickable (renderers show `text (url)`), and any string is valid input (the parser never fails).

## Nodes

Blocks: `{t:"h",level:1|2|3,c:Inline[]}`, `{t:"p",c:Inline[]}`, `{t:"ul",items:Inline[][]}`,
`{t:"ol",items:Inline[][]}`, `{t:"todo",items:[{done:bool,c:Inline[]}]}`, `{t:"code",text:string}`, `{t:"hr"}`.
Inlines: `{t:"text",v}`, `{t:"b",c:Inline[]}`, `{t:"i",c:Inline[]}`, `{t:"code",v}`, `{t:"link",text,url}`.
A `link` is a node even for `javascript:` URLs. Empty `text` nodes are never emitted and adjacent `text` nodes are
always merged. Ordered-list numbers are not kept (renderers number the items 1, 2, 3...).

## Preprocessing

1. Replace every `\r\n` and every lone `\r` with `\n`.
2. If the result is longer than 20 000 UTF-16 code units (JS/Kotlin `length`, Swift `utf16.count`), do not parse:
   return one paragraph holding the whole text: `[{t:"p",c:[{t:"text",v:input}]}]` (exactly 20 000 is still parsed).
3. Split on `\n` (a trailing `\n` leaves a final empty line). Empty input gives `[]`.

All markers are ASCII, so indexing by UTF-16 unit, scalar or byte gives identical results.

## Blocks (line by line, first match wins, nothing is trimmed unless stated)

"Blank" = only spaces and tabs (or empty). "Trim" = remove leading and trailing spaces and tabs only.

1. **Fence**: line starts with ```` ``` ```` (rest of the line, e.g. a language, is ignored). Following lines up to,
   not including, the next line that starts with ```` ``` ```` form `code.text` joined with `\n` (verbatim, no inline
   parsing). The closing line is consumed. An unclosed fence runs to the end of the input. `` ```\n``` `` is `text:""`.
2. **Blank**: ends the current paragraph and the current list.
3. **Rule**: the line is exactly `---`.
4. **Heading**: `#`, `##` or `###`, then one space, then text whose trim is not empty; `c` = inline parse of the
   trimmed text. `####`, `#x` and `# ` (no text) are not headings. A line containing U+2028 or U+2029
   anywhere is never a heading (the reference regex's `.` does not match them), so it falls through to the later
   rules (paragraph text, or a list item if it starts like one); every port must test for these two characters.
5. **List item** (marker at column 0; an indented marker is paragraph text):
   - `- [ ] ` is a todo (not done); `- [x] ` or `- [X] ` is a todo (done);
   - else `- ` or `* ` is a bullet; else ASCII digits `+` `. ` is a numbered item.
   The item text is the rest of the line, trimmed, inline parsed (may be empty). Consecutive items of the same kind
   (`ul`/`ol`/`todo`) join one list node; a different kind starts a new node. A blank line or any non-item line ends
   the list (no continuation lines). `- [ ]x` (no space after the bracket) is a bullet with text `[ ]x`.
6. **Paragraph**: any other line. Consecutive paragraph lines (until a blank line or a fence, rule, heading or
   list-item line) join with `\n` (lines are not trimmed) and are inline parsed as one string, so inline markers may
   span lines.

## Inline (left to right, at each position try in this order, otherwise the character is literal text)

1. **Code span**: `` ` `` then at least one character then the next `` ` ``. `c`/`v` is the text between, verbatim.
   No closing backtick, or an immediately closing one (` `` `), makes the backtick literal (advance one character).
2. **Link**: `text`. `text` runs to the first `]` after the `[`, is not empty and has no `\n`; `(` follows the
   `]` directly; `url` is not empty, has no space, tab or `\n`, and runs to the first `)` that is not balanced by an
   earlier `(` inside the url (so `https://x/a_(b)` and `javascript:alert(1)` keep their parentheses). `text` is
   not parsed further. Anything else: the `[` is literal.
3. **Bold** `**x**`, then 4. **Italic** `*x*`: `**` (or `*` when not `**`) must be followed by a character that is not a
   space, tab or `\n`. The closer is the first marker after at least one content character that follows a character
   that is not a space, tab or `\n`; while searching, code spans and links are skipped whole (so `**a `b**` c` has no
   bold), and when searching for `*` any `**` pair is skipped as a unit. The content is inline parsed
   recursively. No closer: the first `*` is literal and scanning continues at the next character (a failed `**` is
   not retried as italic at the same position; the second `*` is tried by itself).

Implementation note: a naive scan per opener is quadratic (every unclosed `*` rescans to the end). The scan's steps
(skip a code span or link starting here, else skip `**` when looking for `*`, else advance one) do not depend on where
the scan began, so compute once per inline run, right to left, the skip table and the "first closer from here" table
for each marker; each opener is then O(1). Link `)` matching is a prefix-balance lookup, not a rescan. Nested
formatting is at most two or three levels deep in this grammar (the first closer always wins), so recursion is shallow.

`_` is not a marker. Everything else, including `<script>`, `&amp;`, `#` in the middle of a line, is plain text.
