package app.localgatekeys.core.security

/**
 * IDNA tables the lookalike parser needs for the UTS-46 CheckJoiners rule (RFC 5892 Appendix A), as the desktop's
 * `idna.valid_contextj` applies it. Generated from the Python `idna` package 3.20 (`idnadata.joining_types`)
 * and `unicodedata` 16.0.0 (canonical combining class 9, virama). Hex code points, `a-b` = inclusive range.
 */
internal object IdnaTables {
    const val JOINING_L =
        "a872 10acd 10ad7 10d00 10ed9-10eee 10fcb"

    const val JOINING_D =
        "620 626 628 62a-62e 633-63f 641-647 649-64a 66e-66f 678-687 69a-6bf 6c1-6c2 6cc 6ce 6d0-6d1 6fa-6fc " +
        "6ff 712-714 71a-71d 71f-727 729 72b 72d-72e 74e-758 75c-76a 76d-770 772 775-777 77a-77f 7ca-7ea " +
        "841-845 848 84a-853 855 860 862-865 868 886 889-88d 88f 8a0-8a9 8af-8b0 8b3-8b8 8ba-8c8 1807 " +
        "1820-1878 1887-18a8 18aa a840-a871 10ac0-10ac4 10ad3-10ad6 10ad8-10adc 10ade-10ae0 10aeb-10aee 10b80 " +
        "10b82 10b86-10b88 10b8a-10b8b 10b8d 10b90 10bad-10bae 10d01-10d21 10d23 10ec3-10ec4 10ec6-10ec7 " +
        "10f30-10f32 10f34-10f44 10f51-10f53 10f70-10f73 10f76-10f81 10fb0 10fb2-10fb3 10fb8 10fbb-10fbc " +
        "10fbe-10fbf 10fc1 10fc4 10fca 1e900-1e943"

    const val JOINING_R =
        "622-625 627 629 62f-632 648 671-673 675-677 688-699 6c0 6c3-6cb 6cd 6cf 6d2-6d3 6d5 6ee-6ef 710 " +
        "715-719 71e 728 72a 72c 72f 74d 759-75b 76b-76c 771 773-774 778-779 840 846-847 849 854 856-858 867 " +
        "869-86a 870-882 88e 8aa-8ac 8ae 8b1-8b2 8b9 10ac5 10ac7 10ac9-10aca 10ace-10ad2 10add 10ae1 10ae4 " +
        "10aef 10b81 10b83-10b85 10b89 10b8c 10b8e-10b8f 10b91 10ba9-10bac 10d22 10ec2 10f33 10f54 " +
        "10f74-10f75 10fb4-10fb6 10fb9-10fba 10fbd 10fc2-10fc3 10fc9"

    const val JOINING_T =
        "ad 300-36f 483-489 591-5bd 5bf 5c1-5c2 5c4-5c5 5c7-5c9 610-61a 61c 64b-65f 670 6d6-6dc 6df-6e4 " +
        "6e7-6e8 6ea-6ed 70f 711 730-74a 7a6-7b0 7eb-7f3 7fd 816-819 81b-823 825-827 829-82d 859-85b 897-89f " +
        "8ca-8e1 8e3-902 93a 93c 941-948 94d 951-957 962-963 981 9bc 9c1-9c4 9cd 9e2-9e3 9fe a01-a02 a3c " +
        "a41-a42 a47-a48 a4b-a4d a51 a70-a71 a75 a81-a82 abc ac1-ac5 ac7-ac8 acd ae2-ae3 afa-aff b01 b3c b3f " +
        "b41-b44 b4d b53-b56 b62-b63 b82 bc0 bcd c00 c04 c3c c3e-c40 c46-c48 c4a-c4d c55-c56 c62-c63 c81 cbc " +
        "cbf cc6 ccc-ccd ce2-ce3 d00-d01 d3b-d3c d41-d44 d4d d62-d63 d81 dca dd2-dd4 dd6 e31 e34-e3a e47-e4e " +
        "eb1 eb4-ebc ec8-ece f18-f19 f35 f37 f39 f71-f7e f80-f84 f86-f87 f8d-f97 f99-fbc fc6 102d-1030 " +
        "1032-1037 1039-103a 103d-103e 1058-1059 105e-1060 1071-1074 1082 1085-1086 108d 109d 135d-135f " +
        "1712-1714 1732-1733 1752-1753 1772-1773 17b4-17b5 17b7-17bd 17c6 17c9-17d3 17dd 180b-180d 180f " +
        "1885-1886 18a9 1920-1922 1927-1928 1932 1939-193b 1a17-1a18 1a1b 1a56 1a58-1a5e 1a60 1a62 1a65-1a6c " +
        "1a73-1a7c 1a7f 1ab0-1af0 1b00-1b03 1b34 1b36-1b3a 1b3c 1b42 1b6b-1b73 1b80-1b81 1ba2-1ba5 1ba8-1ba9 " +
        "1bab-1bad 1be6 1be8-1be9 1bed 1bef-1bf1 1c2c-1c33 1c36-1c37 1cd0-1cd2 1cd4-1ce0 1ce2-1ce8 1ced 1cf4 " +
        "1cf8-1cf9 1dc0-1dff 200b 200e-200f 202a-202e 2060-2064 206a-206f 20d0-20f0 2cef-2cf1 2d7f 2de0-2dff " +
        "302a-302d 3099-309a a66f-a672 a674-a67d a69e-a69f a6f0-a6f1 a802 a806 a80b a825-a826 a82c a8c4-a8c5 " +
        "a8e0-a8f1 a8ff a926-a92d a947-a951 a980-a982 a9b3 a9b6-a9b9 a9bc-a9bd a9e5 aa29-aa2e aa31-aa32 " +
        "aa35-aa36 aa43 aa4c aa7c aab0 aab2-aab4 aab7-aab8 aabe-aabf aac1 aaec-aaed aaf6 abe5 abe8 abed fb1e " +
        "fe00-fe0f fe20-fe2f feff fff9-fffb 101fd 102e0 10376-1037a 10a01-10a03 10a05-10a06 10a0c-10a0f " +
        "10a38-10a3a 10a3f 10ae5-10ae6 10d24-10d27 10d69-10d6d 10eab-10eac 10ecb-10ecf 10ef0-10eff " +
        "10f46-10f50 10f82-10f85 11001 11038-11046 11070 11073-11074 1107f-11081 110b3-110b6 110b9-110ba " +
        "110c2 11100-11102 11127-1112b 1112d-11134 11173 11180-11181 111b6-111be 111c9-111cc 111cf " +
        "1122f-11231 11234 11236-11237 1123e 11241 112df 112e3-112ea 11300-11301 1133b-1133c 11340 " +
        "11366-1136c 11370-11374 113bb-113c0 113ce 113d0 113d2 113e1-113e2 11438-1143f 11442-11444 11446 " +
        "1145e 114b3-114b8 114ba 114bf-114c0 114c2-114c3 115b2-115b5 115bc-115bd 115bf-115c0 115dc-115dd " +
        "11633-1163a 1163d 1163f-11640 116ab 116ad 116b0-116b5 116b7 1171d 1171f 11722-11725 11727-1172b " +
        "1182f-11837 11839-1183a 1193b-1193c 1193e 11943 119d4-119d7 119da-119db 119e0 11a01-11a0a " +
        "11a33-11a38 11a3b-11a3e 11a47 11a51-11a56 11a59-11a5b 11a8a-11a96 11a98-11a99 11b60 11b62-11b64 " +
        "11b66 11c30-11c36 11c38-11c3d 11c3f 11c92-11ca7 11caa-11cb0 11cb2-11cb3 11cb5-11cb6 11d31-11d36 " +
        "11d3a 11d3c-11d3d 11d3f-11d45 11d47 11d90-11d91 11d95 11d97 11df0 11ef3-11ef4 11f00-11f01 " +
        "11f36-11f3a 11f40 11f42 11f5a 13430-13440 13447-13455 1611e-16129 1612d-1612f 16af0-16af4 " +
        "16b30-16b36 16f4f 16f8f-16f92 16fe4 1bc9d-1bc9e 1bca0-1bca3 1cf00-1cf2d 1cf30-1cf46 1d127-1d128 " +
        "1d167-1d169 1d173-1d182 1d185-1d18b 1d1aa-1d1ad 1d242-1d244 1d25b-1d25c 1da00-1da36 1da3b-1da6c " +
        "1da75 1da84 1da9b-1da9f 1daa1-1daaf 1e000-1e006 1e008-1e018 1e01b-1e021 1e023-1e024 1e026-1e02a " +
        "1e08f 1e130-1e136 1e2ae 1e2ec-1e2ef 1e4ec-1e4ef 1e5ee-1e5ef 1e6e3 1e6e6 1e6ee-1e6ef 1e6f5 " +
        "1e8d0-1e8d6 1e944-1e94b e0001 e0020-e007f e0100-e01ef"

    const val VIRAMA =
        "94d 9cd a4d acd b4d bcd c4d ccd d3b d3c d4d dca e3a eba f84 1039 103a 1714 1715 1734 17d2 1a60 1b44 " +
        "1baa 1bab 1bf2 1bf3 2d7f a806 a82c a8c4 a953 a9c0 aaf6 abed 10a3f 11046 11070 1107f 110b9 11133 " +
        "11134 111c0 11235 112ea 1134d 113ce 113cf 113d0 11442 114c2 115bf 1163f 116b6 1172b 11839 1193d " +
        "1193e 119e0 11a34 11a47 11a99 11c3f 11d44 11d45 11d97 11f41 11f42 1612f"

    /** Sorted inclusive ranges from a table above. */
    fun ranges(table: String): Array<IntArray> = table.split(' ').filter { it.isNotEmpty() }.map { item ->
        val dash = item.indexOf('-')
        if (dash < 0) intArrayOf(item.toInt(16), item.toInt(16)) else intArrayOf(item.substring(0, dash).toInt(16), item.substring(dash + 1).toInt(16))
    }.toTypedArray()

    fun contains(ranges: Array<IntArray>, cp: Int): Boolean {
        var lo = 0
        var hi = ranges.size - 1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            val r = ranges[mid]
            when {
                cp < r[0] -> hi = mid - 1
                cp > r[1] -> lo = mid + 1
                else -> return true
            }
        }
        return false
    }
}
