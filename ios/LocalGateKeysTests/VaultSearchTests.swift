import XCTest
import AppShared
@testable import LocalGateKeys

func rec(_ o: [String: JSONValue]) -> JSONValue { .object(o) }
func strs(_ a: [String]) -> JSONValue { .array(a.map { .string($0) }) }

let webLogin = rec(["id": .string("w1"), "kind": .string("web"), "label": .string("Example account"),
                    "username": .string("Sample.User@example.com"), "password": .string("Maple-Orbit-7731"),
                    "notes": .string("rotated from the desk PC"), "scope": rec(["origin": .string("https://accounts.example.com")]),
                    "tags": strs(["Personal"]), "favorite": .bool(false), "updated_at": .int(1_790_000_500),
                    "totp": rec(["algorithm": .string("SHA1"), "digits": .int(6), "period": .int(30), "secret": .string("JBSWY3DPEHPK3PXP")])])
let deskLogin = rec(["id": .string("d1"), "kind": .string("desktop"), "label": .string("Sample Mail Client"),
                     "username": .string("mailer"), "password": .string("desk-pass"),
                     "scope": rec(["exe_path": .string("C:/Program Files/SampleMail/samplemail.exe")]),
                     "tags": strs([]), "favorite": .bool(true), "updated_at": .int(1_789_000_000)])
let note = rec(["id": .string("n1"), "kind": .string("note"), "title": .string("Wi-Fi at the cabin"),
                "payload": rec(["body": .string("Router behind the pantry door"), "fields": .array([])]),
                "tags": strs(["home"]), "favorite": .bool(true), "updated_at": .int(1_789_956_800)])
let card = rec(["id": .string("c1"), "kind": .string("card"), "title": .string("Travel card"),
                "payload": rec(["brand": .string("visa"), "number": .string("4111111111111111"), "cvv": .string("123")]),
                "tags": strs([]), "updated_at": .int(1_789_999_950)])

func snapshot(_ records: [JSONValue], extra: [String: JSONValue] = [:], deleted: Set<String> = []) -> StoreSnapshot {
    var rs: [String: JSONValue] = extra; var meta: [String: SyncMeta] = [:]
    for r in records {
        guard case .object(let o) = r, case .string(let id)? = o["id"], case .string(let k)? = o["kind"] else { continue }
        rs[id] = Wrapper.make(ns: (k == "web" || k == "desktop") ? .entry : .item, record: r)
        if deleted.contains(id) { meta[id] = SyncMeta(digest: nil, body: nil, updatedAt: nil, vv: [:], deleted: true, deletedAt: 1) }
    }
    return StoreSnapshot(records: rs, meta: meta)
}

final class VaultSearchTests: XCTestCase {
    let items = VaultItem.items(from: snapshot([webLogin, deskLogin, note, card]))

    func ids(_ q: String) -> [String] { VaultSearch.rank(items, query: q).map(\.id) }

    func test_decodes_titles_and_targets_like_the_desktop() {
        let byID = Dictionary(uniqueKeysWithValues: items.map { ($0.id, $0) })
        XCTAssertEqual(byID["w1"]?.title, "Example account")
        XCTAssertEqual(byID["w1"]?.target, "https://accounts.example.com")
        XCTAssertEqual(byID["d1"]?.target, "samplemail.exe")
        XCTAssertEqual(byID["c1"]?.target, "Visa")
        XCTAssertEqual(byID["n1"]?.kindLabel, "Note")
        XCTAssertEqual(byID["c1"]?.kindLabel, "Payment card")
    }

    func test_card_subtitle_is_masked_last_four_with_expiry() {
        func item(_ payload: [String: JSONValue]) -> VaultItem? {
            VaultItem(id: "c", record: ["kind": .string("card"), "title": .string("Visa"), "payload": .object(payload)])
        }
        let withExpiry = item(["brand": .string("visa"), "number": .string("4000 0000 0002 6411"), "expiry": .string("08/27")])
        XCTAssertEqual(withExpiry?.listSubtitle, "•••• 6411 · 08/27")
        XCTAssertFalse(withExpiry?.listSubtitle.contains("40000000") ?? true)
        XCTAssertEqual(item(["brand": .string("visa"), "number": .string("4111111111111111")])?.listSubtitle, "•••• 1111")
        XCTAssertEqual(item(["brand": .string("visa"), "number": .string("41")])?.listSubtitle, "Visa")
        XCTAssertEqual(item(["brand": .string("visa")])?.listSubtitle, "Visa")
        let byID = Dictionary(uniqueKeysWithValues: items.map { ($0.id, $0) })
        XCTAssertEqual(byID["c1"]?.listSubtitle, "•••• 1111")
        XCTAssertTrue(VaultSearch.rank(items, query: "4111111111111111").isEmpty)
    }

    func test_web_title_equal_to_origin_shows_friendly_host() {
        let r = rec(["id": .string("w2"), "kind": .string("web"), "label": .string("https://login.example.org"),
                     "username": .string(""), "password": .string(""), "scope": rec(["origin": .string("https://login.example.org")])])
        XCTAssertEqual(VaultItem.items(from: snapshot([r])).first?.title, "example.org")
    }

    func test_skips_tombstones_and_licences() {
        let lic = Wrapper.make(ns: .license, record: rec(["x": .int(1)]))
        let got = VaultItem.items(from: snapshot([webLogin, note], extra: ["license-abc": lic], deleted: ["n1"]))
        XCTAssertEqual(got.map(\.id), ["w1"])
    }

    func test_empty_query_returns_everything_most_recent_first() {
        XCTAssertEqual(ids("  "), ["w1", "c1", "n1", "d1"])
    }

    func test_search_is_case_insensitive_over_title_username_url_kind_and_tags() {
        XCTAssertEqual(ids("EXAMPLE ACCOUNT"), ["w1"])
        XCTAssertEqual(ids("sample.user"), ["w1"])
        XCTAssertEqual(ids("ACCOUNTS.example"), ["w1"])
        XCTAssertEqual(ids("samplemail.exe"), ["d1"])
        XCTAssertEqual(ids("payment"), ["c1"])
        XCTAssertEqual(ids("personal"), ["w1"])
        XCTAssertEqual(ids("HOME"), ["n1"])
    }

    func test_secrets_notes_and_payloads_are_never_searched() {
        XCTAssertEqual(ids("Maple-Orbit"), [])
        XCTAssertEqual(ids("rotated"), [])
        XCTAssertEqual(ids("pantry"), [])
        XCTAssertEqual(ids("4111"), [])
    }

    func test_every_token_must_match() {
        XCTAssertEqual(ids("example personal"), ["w1"])
        XCTAssertEqual(ids("example home"), [])
    }

    func test_prefix_tokens_restrict_one_field() {
        XCTAssertEqual(ids("tag:home"), ["n1"])
        XCTAssertEqual(ids("user:mailer"), ["d1"])
        XCTAssertEqual(ids("url:accounts"), ["w1"])
        XCTAssertEqual(ids("type:card"), ["c1"])
        XCTAssertEqual(ids("tag:"), ids(""))          // empty prefix value is ignored
        XCTAssertEqual(ids("foo:bar"), [])            // unknown prefix stays literal
    }

    func test_rank_exact_then_prefix_then_contains() {
        let a = rec(["id": .string("a"), "kind": .string("note"), "title": .string("my bank"), "updated_at": .int(3)])
        let b = rec(["id": .string("b"), "kind": .string("note"), "title": .string("bank"), "updated_at": .int(1)])
        let c = rec(["id": .string("c"), "kind": .string("note"), "title": .string("bank of x"), "updated_at": .int(2)])
        let got = VaultSearch.rank(VaultItem.items(from: snapshot([a, b, c])), query: "Bank").map(\.id)
        XCTAssertEqual(got, ["b", "c", "a"])
    }

    func test_fuzzy_match_like_difflib() {
        XCTAssertEqual(ids("exmaple"), ["w1"])  // close to "example"
        XCTAssertEqual(ids("zq"), [])           // too short for fuzzy, no substring hit
        XCTAssertEqual(SequenceRatio.ratio("exmaple", "example"), 6.0 * 2 / 14, accuracy: 1e-9)
    }

    func test_nfc_and_nfd_are_different_like_python() {
        let nfc = "caf\u{E9}", nfd = "cafe\u{301}"
        let r = rec(["id": .string("u1"), "kind": .string("note"), "title": .string(nfc), "updated_at": .int(1)])
        let items = VaultItem.items(from: snapshot([r]))
        XCTAssertEqual(VaultSearch.rank(items, query: nfc).map(\.id), ["u1"])
        XCTAssertEqual(VaultSearch.tokenRank(VaultSearch.fields(items[0]), nil, nfc), VaultSearch.rankExact)
        XCTAssertNotEqual(VaultSearch.tokenRank(VaultSearch.fields(items[0]), nil, nfd), VaultSearch.rankExact)
        XCTAssertFalse(Scalars.contains(nfc, "e"))
        XCTAssertTrue(Scalars.hasPrefix(nfd, "cafe"))
        XCTAssertEqual(VaultSearch.words("na\u{EF}ve-x"), ["na", "ve", "x"])
        XCTAssertEqual(VaultSearch.casefold("STRASSE \u{DF} \u{C9}"), "strasse ss \u{E9}")
    }

    func test_type_filters() {
        XCTAssertEqual(VaultSearch.filterOptions(items).map(\.label),
                       ["All types", "Favorites", "Browser", "Desktop", "Note", "Payment card"])
        XCTAssertEqual(VaultSearch.apply(items, query: "", filter: .kind("note")).map(\.id), ["n1"])
        XCTAssertEqual(VaultSearch.apply(items, query: "", filter: .favorites).map(\.id), ["n1", "d1"])
        XCTAssertEqual(VaultSearch.apply(items, query: "sample", filter: .kind("web")).map(\.id), ["w1"])
    }

    @MainActor
    func test_list_model_loads_and_filters() throws {
        let m = VaultListModel(store: MemoryStore(snapshot([webLogin, note])))
        m.reload()
        XCTAssertEqual(m.visibleItems.map(\.id), ["w1", "n1"])
        m.query = "cabin"; XCTAssertEqual(m.visibleItems.map(\.id), ["n1"])
        m.query = ""; m.filter = .kind("web"); XCTAssertEqual(m.visibleItems.map(\.id), ["w1"])
    }
}
