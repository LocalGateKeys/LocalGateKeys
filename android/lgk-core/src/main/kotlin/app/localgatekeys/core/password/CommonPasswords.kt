package app.localgatekeys.core.password

/**
 * The desktop's `password_tools.COMMON_PASSWORDS` (640 entries, most common first), copied verbatim
 * by a script from src/localvault/password_tools.py. The rank of each (first occurrence, lower-cased) feeds the
 * dictionary guess estimate.
 */
internal object CommonPasswords {
    val list: List<String> = listOf(
    "123456", "password", "123456789", "12345678", "12345", "1234567", "qwerty", "111111", "1234567890", "123123",
    "abc123", "1234", "password1", "iloveyou", "1q2w3e4r", "000000", "qwerty123", "zaq12wsx", "dragon", "sunshine",
    "princess", "letmein", "654321", "monkey", "27653", "1qaz2wsx", "123321", "qwertyuiop", "superman", "asdfghjkl",
    "password123", "admin", "welcome", "login", "football", "baseball", "master", "hello", "freedom", "whatever",
    "qazwsx", "trustno1", "starwars", "shadow", "michael", "jennifer", "jordan", "hunter", "buster", "soccer", "harley",
    "batman", "andrew", "tigger", "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "klaster", "112233",
    "george", "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111", "131313", "freedom1",
    "777777", "pass", "maggie", "159753", "aaaaaa", "ginger", "joshua", "cheese", "amanda", "summer", "love", "ashley",
    "nicole", "chelsea", "biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin", "thunder", "taylor",
    "matrix", "mobilemail", "mom", "monitor", "monitoring", "montana", "moon", "moscow", "william", "corvette",
    "hello123", "martin", "heather", "secret", "merlin", "diamond", "1234qwer", "gfhjkm", "hammer", "silver", "222222",
    "88888888", "anthony", "justin", "test", "bailey", "q1w2e3r4t5", "patrick", "internet", "scooter", "orange",
    "11111", "golfer", "cookie", "richard", "samantha", "bigdog", "guitar", "jackson", "whatever1", "anything",
    "google", "facebook", "liverpool", "chicken", "mustang", "midnight", "rainbow", "flower", "purple", "angel",
    "junior", "nathan", "arsenal", "chelsea1", "cowboys", "eagles", "steelers", "lakers", "rangers", "yellow", "camaro",
    "secret1", "dick", "falcon", "iceman", "tigers", "boomer", "miller", "nascar", "banana", "hotdog", "killer",
    "jasper", "zxcvbnm1", "asdfgh", "asdf1234", "a123456", "123qwe", "qwe123", "1q2w3e", "azerty", "loveme", "fuckyou",
    "pokemon", "696969", "kitten", "lol123", "snoopy", "123654", "abcd1234", "abcdef", "abcdefg", "abcdefgh",
    "passw0rd", "p@ssw0rd", "P@ssw0rd", "Password", "Password1", "Password123", "Welcome1", "welcome1", "Admin123",
    "admin123", "root", "toor", "changeme", "default", "guest", "letmein1", "qwerty1", "qwerty12", "qwerty1234",
    "1q2w3e4r5t", "123abc", "123456a", "123456789a", "12345678a", "1234561", "12345679", "1234554321", "123123123",
    "1234512345", "121212", "7777777", "666666", "999999", "888888", "333333", "444444", "123789", "456789",
    "147258369", "159357", "741852963", "963852741", "102030", "112112", "123000", "100200", "1q2w3e4r5t6y", "qwertyui",
    "qwertyu", "qweasdzxc", "asdasd", "asd123", "zxczxc", "qweqwe", "poiuyt", "mnbvcxz", "lkjhgfdsa", "ytrewq",
    "asdfasdf", "zxcvbnm", "iloveyou1", "iloveyou2", "iloveu", "lovely", "loveyou", "sweety", "babygirl", "baby",
    "angel1", "angels", "princess1", "flowers", "butterfly", "bubbles", "cupcake", "chocolate", "vanilla", "cookies",
    "pumpkin", "peanut", "jesus", "jesus1", "blessed", "heaven", "trinity", "faith", "hope", "grace", "peace",
    "forever", "friends", "family", "mother", "father", "brother", "sister", "daddy", "mommy", "grandma", "sunshine1",
    "spring", "winter", "autumn", "december", "november", "october", "september", "august", "july", "june", "january",
    "february", "march", "april", "monday", "friday", "saturday", "sunday", "tuesday", "thursday", "america", "canada",
    "london", "paris", "berlin", "madrid", "rome", "tokyo", "sydney", "boston", "newyork", "chicago", "houston",
    "denver", "phoenix", "seattle", "miami", "atlanta", "vegas", "texas", "florida", "california", "carolina",
    "georgia", "virginia", "mexico", "brazil", "italia", "espana", "france", "ferrari", "porsche", "mercedes", "toyota",
    "honda", "nissan", "yamaha", "harley1", "jaguar", "lincoln", "cowboy", "soldier", "warrior", "knight", "wizard",
    "ninja", "pirate", "samurai", "viking", "gladiator", "spider", "spiderman", "ironman", "hulk", "thor", "wolverine",
    "xmen", "avengers", "marvel", "gotham", "gandalf", "frodo", "legolas", "hobbit", "potter", "hermione", "voldemort",
    "dumbledore", "hogwarts", "gryffindor", "pikachu", "charizard", "bulbasaur", "squirtle", "mewtwo", "zelda", "mario",
    "luigi", "sonic", "pacman", "nintendo", "playstation", "xbox", "gamer", "gaming", "minecraft", "fortnite", "roblox",
    "halo", "doom", "metallica", "nirvana", "eminem", "beatles", "slipknot", "rockstar", "music", "guitar1", "drummer",
    "singer", "coffee", "pizza", "burger", "cheese1", "sugar", "candy", "honey", "apple", "cherry", "lemon", "tiger",
    "lion", "bear", "wolf", "eagle", "hawk", "shark", "dolphin", "panda", "koala", "puppy", "doggy", "kitty", "bunny",
    "turtle", "monkey1", "dragon1", "phoenix1", "unicorn", "pegasus", "redsox", "cubs", "dodgers", "giants", "patriots",
    "packers", "broncos", "raiders", "celtics", "bulls", "manchester", "barcelona", "realmadrid", "juventus",
    "chelsea12", "arsenal1", "liverpool1", "ronaldo", "messi", "beckham", "hunter1", "killer1", "master1", "shadow1",
    "soccer1", "football1", "baseball1", "hockey1", "basketball", "swimming", "golf", "tennis", "cricket", "rugby",
    "boxing", "skate", "surfer", "runner", "biker", "racing", "nothing", "something", "anything1", "everything",
    "whocares", "idontknow", "letmein123", "openup", "opensesame", "trustme", "temp", "temp123", "test123", "test1234",
    "testing", "tester", "demo", "demo123", "sample", "example", "user", "user123", "username", "administrator",
    "manager", "operator", "service", "support", "system", "server", "oracle", "mysql", "postgres", "cisco", "linux",
    "windows", "ubuntu", "debian", "apple123", "android", "secure", "security", "private", "hidden", "locked", "unlock",
    "access1", "accessdenied", "enter", "entry", "money", "money1", "cash", "rich", "dollar", "million", "millionaire",
    "winner", "lucky", "lucky7", "blink182", "green day", "linkinpark", "fuckoff", "bitch", "asshole", "sexy", "hottie",
    "cutie", "badboy", "jordan23", "kobe24", "lebron23", "number1", "number one", "one", "two", "three", "four", "five",
    "abc", "xyz", "aaa", "aaaa", "aaaaa", "aaaaaaa", "aaaaaaaa", "qqqqqq", "zzzzzz", "xxxxxx", "1234567891",
    "12345678910", "0123456789", "01234567", "0987654321", "9876543210", "87654321", "7654321", "654321a", "321654",
    "123qweasd", "qweasd", "qwerasdf", "1qazxsw2", "1qaz2wsx3edc", "zaq1xsw2", "!qaz2wsx", "1qazzaq1", "qaz123",
    "wsx123", "nicole1", "jessica1", "ashley1", "amanda1", "michael1", "daniel1", "jordan1", "andrew1", "joshua1",
    "matthew1", "hannah", "sophia", "olivia", "emily", "emma", "madison", "isabella", "abigail", "elizabeth",
    "victoria", "james", "john", "david", "chris", "mike", "steve", "kevin", "brian", "jason", "ryan", "tiffany",
    "brittany", "stephanie", "melissa", "rebecca", "lauren", "kimberly", "courtney", "danielle", "christina",
    "alexander", "alexandra", "alex", "sam", "max", "tom", "ben", "joe", "dan", "rob",
    )

    /** Lower-cased password -> rank (1-based, first occurrence wins), as desktop `_COMMON_RANK`. */
    val rank: Map<String, Int> by lazy {
        val m = HashMap<String, Int>()
        list.forEachIndexed { i, v -> m.putIfAbsent(StrengthEstimator.pyLower(v), i + 1) }
        m
    }
}
