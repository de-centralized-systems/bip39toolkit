#!/usr/bin/env python3
from __future__ import annotations

VERSION = "0.1.0"


import collections
import hashlib
import hmac
import itertools
import math
import re
import secrets
import shutil
import sys
import textwrap
import time
import typing
import unicodedata


########################################################################################################################
### BIP39 encoding and decoding ########################################################################################
########################################################################################################################
###                                                                                                                  ###
### Helper functions to convert from and to BIP39 compatible mnemonic phrases.                                       ###
### This implementation deliberately considers only the official english word list.                                  ###
###                                                                                                                  ###
### Correspondence between the number of words (MS), bits of entropy (ENT) and checksum length (CS):                 ###
###                                                                                                                  ###
### CS = ENT / 32                                                                                                    ###
### MS = (ENT + CS) / 11                                                                                             ###
###                                                                                                                  ###
### |  ENT  | CS | ENT+CS |  MS  |                                                                                   ###
### +-------+----+--------+------+                                                                                   ###
### |  128  |  4 |   132  |  12  |                                                                                   ###
### |  160  |  5 |   165  |  15  |                                                                                   ###
### |  192  |  6 |   198  |  18  |                                                                                   ###
### |  224  |  7 |   231  |  21  |                                                                                   ###
### |  256  |  8 |   264  |  24  |                                                                                   ###
###                                                                                                                  ###
### See https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki                                               ###
###                                                                                                                  ###
########################################################################################################################


BIP39_BIT_LENGTHS = (128, 160, 192, 224, 256)
BIP39_NUM_WORDS = (12, 15, 18, 21, 24)

BIP39_BIT_LENGTH_TO_WORDS_TABLE = dict(zip(BIP39_BIT_LENGTHS, BIP39_NUM_WORDS))
BIP39_WORDS_TO_BIT_LENGTH_TABLE = dict(zip(BIP39_NUM_WORDS, BIP39_BIT_LENGTHS))


def verify_wordlist(*words: str) -> tuple[str, ...]:
    """Verifies that the words given in this source file match the English wordlist specified in BIP39. The verification
    procedures catches accidental (not deliberate) changes to the wordlist contained with this file.
    The SHA256 hash below is derived from the original wordlist at:
    https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    """
    words_sha256 = hashlib.sha256(("\n".join(words) + "\n").encode()).hexdigest()
    assert words_sha256 == "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    return words


# The BIP39 wordlist (English) is directly integrated to this Python file to make it a standalone file.
# Used by the encode function to map 0-based word indices to the specified words.
# fmt: off
BIP39_WORDLIST: tuple[str, ...] = verify_wordlist(
    "abandon",  "ability",  "able",     "about",    "above",    "absent",   "absorb",   "abstract",
    "absurd",   "abuse",    "access",   "accident", "account",  "accuse",   "achieve",  "acid",
    "acoustic", "acquire",  "across",   "act",      "action",   "actor",    "actress",  "actual",
    "adapt",    "add",      "addict",   "address",  "adjust",   "admit",    "adult",    "advance",
    "advice",   "aerobic",  "affair",   "afford",   "afraid",   "again",    "age",      "agent",
    "agree",    "ahead",    "aim",      "air",      "airport",  "aisle",    "alarm",    "album",
    "alcohol",  "alert",    "alien",    "all",      "alley",    "allow",    "almost",   "alone",
    "alpha",    "already",  "also",     "alter",    "always",   "amateur",  "amazing",  "among",
    "amount",   "amused",   "analyst",  "anchor",   "ancient",  "anger",    "angle",    "angry",
    "animal",   "ankle",    "announce", "annual",   "another",  "answer",   "antenna",  "antique",
    "anxiety",  "any",      "apart",    "apology",  "appear",   "apple",    "approve",  "april",
    "arch",     "arctic",   "area",     "arena",    "argue",    "arm",      "armed",    "armor",
    "army",     "around",   "arrange",  "arrest",   "arrive",   "arrow",    "art",      "artefact",
    "artist",   "artwork",  "ask",      "aspect",   "assault",  "asset",    "assist",   "assume",
    "asthma",   "athlete",  "atom",     "attack",   "attend",   "attitude", "attract",  "auction",
    "audit",    "august",   "aunt",     "author",   "auto",     "autumn",   "average",  "avocado",
    "avoid",    "awake",    "aware",    "away",     "awesome",  "awful",    "awkward",  "axis",
    "baby",     "bachelor", "bacon",    "badge",    "bag",      "balance",  "balcony",  "ball",
    "bamboo",   "banana",   "banner",   "bar",      "barely",   "bargain",  "barrel",   "base",
    "basic",    "basket",   "battle",   "beach",    "bean",     "beauty",   "because",  "become",
    "beef",     "before",   "begin",    "behave",   "behind",   "believe",  "below",    "belt",
    "bench",    "benefit",  "best",     "betray",   "better",   "between",  "beyond",   "bicycle",
    "bid",      "bike",     "bind",     "biology",  "bird",     "birth",    "bitter",   "black",
    "blade",    "blame",    "blanket",  "blast",    "bleak",    "bless",    "blind",    "blood",
    "blossom",  "blouse",   "blue",     "blur",     "blush",    "board",    "boat",     "body",
    "boil",     "bomb",     "bone",     "bonus",    "book",     "boost",    "border",   "boring",
    "borrow",   "boss",     "bottom",   "bounce",   "box",      "boy",      "bracket",  "brain",
    "brand",    "brass",    "brave",    "bread",    "breeze",   "brick",    "bridge",   "brief",
    "bright",   "bring",    "brisk",    "broccoli", "broken",   "bronze",   "broom",    "brother",
    "brown",    "brush",    "bubble",   "buddy",    "budget",   "buffalo",  "build",    "bulb",
    "bulk",     "bullet",   "bundle",   "bunker",   "burden",   "burger",   "burst",    "bus",
    "business", "busy",     "butter",   "buyer",    "buzz",     "cabbage",  "cabin",    "cable",
    "cactus",   "cage",     "cake",     "call",     "calm",     "camera",   "camp",     "can",
    "canal",    "cancel",   "candy",    "cannon",   "canoe",    "canvas",   "canyon",   "capable",
    "capital",  "captain",  "car",      "carbon",   "card",     "cargo",    "carpet",   "carry",
    "cart",     "case",     "cash",     "casino",   "castle",   "casual",   "cat",      "catalog",
    "catch",    "category", "cattle",   "caught",   "cause",    "caution",  "cave",     "ceiling",
    "celery",   "cement",   "census",   "century",  "cereal",   "certain",  "chair",    "chalk",
    "champion", "change",   "chaos",    "chapter",  "charge",   "chase",    "chat",     "cheap",
    "check",    "cheese",   "chef",     "cherry",   "chest",    "chicken",  "chief",    "child",
    "chimney",  "choice",   "choose",   "chronic",  "chuckle",  "chunk",    "churn",    "cigar",
    "cinnamon", "circle",   "citizen",  "city",     "civil",    "claim",    "clap",     "clarify",
    "claw",     "clay",     "clean",    "clerk",    "clever",   "click",    "client",   "cliff",
    "climb",    "clinic",   "clip",     "clock",    "clog",     "close",    "cloth",    "cloud",
    "clown",    "club",     "clump",    "cluster",  "clutch",   "coach",    "coast",    "coconut",
    "code",     "coffee",   "coil",     "coin",     "collect",  "color",    "column",   "combine",
    "come",     "comfort",  "comic",    "common",   "company",  "concert",  "conduct",  "confirm",
    "congress", "connect",  "consider", "control",  "convince", "cook",     "cool",     "copper",
    "copy",     "coral",    "core",     "corn",     "correct",  "cost",     "cotton",   "couch",
    "country",  "couple",   "course",   "cousin",   "cover",    "coyote",   "crack",    "cradle",
    "craft",    "cram",     "crane",    "crash",    "crater",   "crawl",    "crazy",    "cream",
    "credit",   "creek",    "crew",     "cricket",  "crime",    "crisp",    "critic",   "crop",
    "cross",    "crouch",   "crowd",    "crucial",  "cruel",    "cruise",   "crumble",  "crunch",
    "crush",    "cry",      "crystal",  "cube",     "culture",  "cup",      "cupboard", "curious",
    "current",  "curtain",  "curve",    "cushion",  "custom",   "cute",     "cycle",    "dad",
    "damage",   "damp",     "dance",    "danger",   "daring",   "dash",     "daughter", "dawn",
    "day",      "deal",     "debate",   "debris",   "decade",   "december", "decide",   "decline",
    "decorate", "decrease", "deer",     "defense",  "define",   "defy",     "degree",   "delay",
    "deliver",  "demand",   "demise",   "denial",   "dentist",  "deny",     "depart",   "depend",
    "deposit",  "depth",    "deputy",   "derive",   "describe", "desert",   "design",   "desk",
    "despair",  "destroy",  "detail",   "detect",   "develop",  "device",   "devote",   "diagram",
    "dial",     "diamond",  "diary",    "dice",     "diesel",   "diet",     "differ",   "digital",
    "dignity",  "dilemma",  "dinner",   "dinosaur", "direct",   "dirt",     "disagree", "discover",
    "disease",  "dish",     "dismiss",  "disorder", "display",  "distance", "divert",   "divide",
    "divorce",  "dizzy",    "doctor",   "document", "dog",      "doll",     "dolphin",  "domain",
    "donate",   "donkey",   "donor",    "door",     "dose",     "double",   "dove",     "draft",
    "dragon",   "drama",    "drastic",  "draw",     "dream",    "dress",    "drift",    "drill",
    "drink",    "drip",     "drive",    "drop",     "drum",     "dry",      "duck",     "dumb",
    "dune",     "during",   "dust",     "dutch",    "duty",     "dwarf",    "dynamic",  "eager",
    "eagle",    "early",    "earn",     "earth",    "easily",   "east",     "easy",     "echo",
    "ecology",  "economy",  "edge",     "edit",     "educate",  "effort",   "egg",      "eight",
    "either",   "elbow",    "elder",    "electric", "elegant",  "element",  "elephant", "elevator",
    "elite",    "else",     "embark",   "embody",   "embrace",  "emerge",   "emotion",  "employ",
    "empower",  "empty",    "enable",   "enact",    "end",      "endless",  "endorse",  "enemy",
    "energy",   "enforce",  "engage",   "engine",   "enhance",  "enjoy",    "enlist",   "enough",
    "enrich",   "enroll",   "ensure",   "enter",    "entire",   "entry",    "envelope", "episode",
    "equal",    "equip",    "era",      "erase",    "erode",    "erosion",  "error",    "erupt",
    "escape",   "essay",    "essence",  "estate",   "eternal",  "ethics",   "evidence", "evil",
    "evoke",    "evolve",   "exact",    "example",  "excess",   "exchange", "excite",   "exclude",
    "excuse",   "execute",  "exercise", "exhaust",  "exhibit",  "exile",    "exist",    "exit",
    "exotic",   "expand",   "expect",   "expire",   "explain",  "expose",   "express",  "extend",
    "extra",    "eye",      "eyebrow",  "fabric",   "face",     "faculty",  "fade",     "faint",
    "faith",    "fall",     "false",    "fame",     "family",   "famous",   "fan",      "fancy",
    "fantasy",  "farm",     "fashion",  "fat",      "fatal",    "father",   "fatigue",  "fault",
    "favorite", "feature",  "february", "federal",  "fee",      "feed",     "feel",     "female",
    "fence",    "festival", "fetch",    "fever",    "few",      "fiber",    "fiction",  "field",
    "figure",   "file",     "film",     "filter",   "final",    "find",     "fine",     "finger",
    "finish",   "fire",     "firm",     "first",    "fiscal",   "fish",     "fit",      "fitness",
    "fix",      "flag",     "flame",    "flash",    "flat",     "flavor",   "flee",     "flight",
    "flip",     "float",    "flock",    "floor",    "flower",   "fluid",    "flush",    "fly",
    "foam",     "focus",    "fog",      "foil",     "fold",     "follow",   "food",     "foot",
    "force",    "forest",   "forget",   "fork",     "fortune",  "forum",    "forward",  "fossil",
    "foster",   "found",    "fox",      "fragile",  "frame",    "frequent", "fresh",    "friend",
    "fringe",   "frog",     "front",    "frost",    "frown",    "frozen",   "fruit",    "fuel",
    "fun",      "funny",    "furnace",  "fury",     "future",   "gadget",   "gain",     "galaxy",
    "gallery",  "game",     "gap",      "garage",   "garbage",  "garden",   "garlic",   "garment",
    "gas",      "gasp",     "gate",     "gather",   "gauge",    "gaze",     "general",  "genius",
    "genre",    "gentle",   "genuine",  "gesture",  "ghost",    "giant",    "gift",     "giggle",
    "ginger",   "giraffe",  "girl",     "give",     "glad",     "glance",   "glare",    "glass",
    "glide",    "glimpse",  "globe",    "gloom",    "glory",    "glove",    "glow",     "glue",
    "goat",     "goddess",  "gold",     "good",     "goose",    "gorilla",  "gospel",   "gossip",
    "govern",   "gown",     "grab",     "grace",    "grain",    "grant",    "grape",    "grass",
    "gravity",  "great",    "green",    "grid",     "grief",    "grit",     "grocery",  "group",
    "grow",     "grunt",    "guard",    "guess",    "guide",    "guilt",    "guitar",   "gun",
    "gym",      "habit",    "hair",     "half",     "hammer",   "hamster",  "hand",     "happy",
    "harbor",   "hard",     "harsh",    "harvest",  "hat",      "have",     "hawk",     "hazard",
    "head",     "health",   "heart",    "heavy",    "hedgehog", "height",   "hello",    "helmet",
    "help",     "hen",      "hero",     "hidden",   "high",     "hill",     "hint",     "hip",
    "hire",     "history",  "hobby",    "hockey",   "hold",     "hole",     "holiday",  "hollow",
    "home",     "honey",    "hood",     "hope",     "horn",     "horror",   "horse",    "hospital",
    "host",     "hotel",    "hour",     "hover",    "hub",      "huge",     "human",    "humble",
    "humor",    "hundred",  "hungry",   "hunt",     "hurdle",   "hurry",    "hurt",     "husband",
    "hybrid",   "ice",      "icon",     "idea",     "identify", "idle",     "ignore",   "ill",
    "illegal",  "illness",  "image",    "imitate",  "immense",  "immune",   "impact",   "impose",
    "improve",  "impulse",  "inch",     "include",  "income",   "increase", "index",    "indicate",
    "indoor",   "industry", "infant",   "inflict",  "inform",   "inhale",   "inherit",  "initial",
    "inject",   "injury",   "inmate",   "inner",    "innocent", "input",    "inquiry",  "insane",
    "insect",   "inside",   "inspire",  "install",  "intact",   "interest", "into",     "invest",
    "invite",   "involve",  "iron",     "island",   "isolate",  "issue",    "item",     "ivory",
    "jacket",   "jaguar",   "jar",      "jazz",     "jealous",  "jeans",    "jelly",    "jewel",
    "job",      "join",     "joke",     "journey",  "joy",      "judge",    "juice",    "jump",
    "jungle",   "junior",   "junk",     "just",     "kangaroo", "keen",     "keep",     "ketchup",
    "key",      "kick",     "kid",      "kidney",   "kind",     "kingdom",  "kiss",     "kit",
    "kitchen",  "kite",     "kitten",   "kiwi",     "knee",     "knife",    "knock",    "know",
    "lab",      "label",    "labor",    "ladder",   "lady",     "lake",     "lamp",     "language",
    "laptop",   "large",    "later",    "latin",    "laugh",    "laundry",  "lava",     "law",
    "lawn",     "lawsuit",  "layer",    "lazy",     "leader",   "leaf",     "learn",    "leave",
    "lecture",  "left",     "leg",      "legal",    "legend",   "leisure",  "lemon",    "lend",
    "length",   "lens",     "leopard",  "lesson",   "letter",   "level",    "liar",     "liberty",
    "library",  "license",  "life",     "lift",     "light",    "like",     "limb",     "limit",
    "link",     "lion",     "liquid",   "list",     "little",   "live",     "lizard",   "load",
    "loan",     "lobster",  "local",    "lock",     "logic",    "lonely",   "long",     "loop",
    "lottery",  "loud",     "lounge",   "love",     "loyal",    "lucky",    "luggage",  "lumber",
    "lunar",    "lunch",    "luxury",   "lyrics",   "machine",  "mad",      "magic",    "magnet",
    "maid",     "mail",     "main",     "major",    "make",     "mammal",   "man",      "manage",
    "mandate",  "mango",    "mansion",  "manual",   "maple",    "marble",   "march",    "margin",
    "marine",   "market",   "marriage", "mask",     "mass",     "master",   "match",    "material",
    "math",     "matrix",   "matter",   "maximum",  "maze",     "meadow",   "mean",     "measure",
    "meat",     "mechanic", "medal",    "media",    "melody",   "melt",     "member",   "memory",
    "mention",  "menu",     "mercy",    "merge",    "merit",    "merry",    "mesh",     "message",
    "metal",    "method",   "middle",   "midnight", "milk",     "million",  "mimic",    "mind",
    "minimum",  "minor",    "minute",   "miracle",  "mirror",   "misery",   "miss",     "mistake",
    "mix",      "mixed",    "mixture",  "mobile",   "model",    "modify",   "mom",      "moment",
    "monitor",  "monkey",   "monster",  "month",    "moon",     "moral",    "more",     "morning",
    "mosquito", "mother",   "motion",   "motor",    "mountain", "mouse",    "move",     "movie",
    "much",     "muffin",   "mule",     "multiply", "muscle",   "museum",   "mushroom", "music",
    "must",     "mutual",   "myself",   "mystery",  "myth",     "naive",    "name",     "napkin",
    "narrow",   "nasty",    "nation",   "nature",   "near",     "neck",     "need",     "negative",
    "neglect",  "neither",  "nephew",   "nerve",    "nest",     "net",      "network",  "neutral",
    "never",    "news",     "next",     "nice",     "night",    "noble",    "noise",    "nominee",
    "noodle",   "normal",   "north",    "nose",     "notable",  "note",     "nothing",  "notice",
    "novel",    "now",      "nuclear",  "number",   "nurse",    "nut",      "oak",      "obey",
    "object",   "oblige",   "obscure",  "observe",  "obtain",   "obvious",  "occur",    "ocean",
    "october",  "odor",     "off",      "offer",    "office",   "often",    "oil",      "okay",
    "old",      "olive",    "olympic",  "omit",     "once",     "one",      "onion",    "online",
    "only",     "open",     "opera",    "opinion",  "oppose",   "option",   "orange",   "orbit",
    "orchard",  "order",    "ordinary", "organ",    "orient",   "original", "orphan",   "ostrich",
    "other",    "outdoor",  "outer",    "output",   "outside",  "oval",     "oven",     "over",
    "own",      "owner",    "oxygen",   "oyster",   "ozone",    "pact",     "paddle",   "page",
    "pair",     "palace",   "palm",     "panda",    "panel",    "panic",    "panther",  "paper",
    "parade",   "parent",   "park",     "parrot",   "party",    "pass",     "patch",    "path",
    "patient",  "patrol",   "pattern",  "pause",    "pave",     "payment",  "peace",    "peanut",
    "pear",     "peasant",  "pelican",  "pen",      "penalty",  "pencil",   "people",   "pepper",
    "perfect",  "permit",   "person",   "pet",      "phone",    "photo",    "phrase",   "physical",
    "piano",    "picnic",   "picture",  "piece",    "pig",      "pigeon",   "pill",     "pilot",
    "pink",     "pioneer",  "pipe",     "pistol",   "pitch",    "pizza",    "place",    "planet",
    "plastic",  "plate",    "play",     "please",   "pledge",   "pluck",    "plug",     "plunge",
    "poem",     "poet",     "point",    "polar",    "pole",     "police",   "pond",     "pony",
    "pool",     "popular",  "portion",  "position", "possible", "post",     "potato",   "pottery",
    "poverty",  "powder",   "power",    "practice", "praise",   "predict",  "prefer",   "prepare",
    "present",  "pretty",   "prevent",  "price",    "pride",    "primary",  "print",    "priority",
    "prison",   "private",  "prize",    "problem",  "process",  "produce",  "profit",   "program",
    "project",  "promote",  "proof",    "property", "prosper",  "protect",  "proud",    "provide",
    "public",   "pudding",  "pull",     "pulp",     "pulse",    "pumpkin",  "punch",    "pupil",
    "puppy",    "purchase", "purity",   "purpose",  "purse",    "push",     "put",      "puzzle",
    "pyramid",  "quality",  "quantum",  "quarter",  "question", "quick",    "quit",     "quiz",
    "quote",    "rabbit",   "raccoon",  "race",     "rack",     "radar",    "radio",    "rail",
    "rain",     "raise",    "rally",    "ramp",     "ranch",    "random",   "range",    "rapid",
    "rare",     "rate",     "rather",   "raven",    "raw",      "razor",    "ready",    "real",
    "reason",   "rebel",    "rebuild",  "recall",   "receive",  "recipe",   "record",   "recycle",
    "reduce",   "reflect",  "reform",   "refuse",   "region",   "regret",   "regular",  "reject",
    "relax",    "release",  "relief",   "rely",     "remain",   "remember", "remind",   "remove",
    "render",   "renew",    "rent",     "reopen",   "repair",   "repeat",   "replace",  "report",
    "require",  "rescue",   "resemble", "resist",   "resource", "response", "result",   "retire",
    "retreat",  "return",   "reunion",  "reveal",   "review",   "reward",   "rhythm",   "rib",
    "ribbon",   "rice",     "rich",     "ride",     "ridge",    "rifle",    "right",    "rigid",
    "ring",     "riot",     "ripple",   "risk",     "ritual",   "rival",    "river",    "road",
    "roast",    "robot",    "robust",   "rocket",   "romance",  "roof",     "rookie",   "room",
    "rose",     "rotate",   "rough",    "round",    "route",    "royal",    "rubber",   "rude",
    "rug",      "rule",     "run",      "runway",   "rural",    "sad",      "saddle",   "sadness",
    "safe",     "sail",     "salad",    "salmon",   "salon",    "salt",     "salute",   "same",
    "sample",   "sand",     "satisfy",  "satoshi",  "sauce",    "sausage",  "save",     "say",
    "scale",    "scan",     "scare",    "scatter",  "scene",    "scheme",   "school",   "science",
    "scissors", "scorpion", "scout",    "scrap",    "screen",   "script",   "scrub",    "sea",
    "search",   "season",   "seat",     "second",   "secret",   "section",  "security", "seed",
    "seek",     "segment",  "select",   "sell",     "seminar",  "senior",   "sense",    "sentence",
    "series",   "service",  "session",  "settle",   "setup",    "seven",    "shadow",   "shaft",
    "shallow",  "share",    "shed",     "shell",    "sheriff",  "shield",   "shift",    "shine",
    "ship",     "shiver",   "shock",    "shoe",     "shoot",    "shop",     "short",    "shoulder",
    "shove",    "shrimp",   "shrug",    "shuffle",  "shy",      "sibling",  "sick",     "side",
    "siege",    "sight",    "sign",     "silent",   "silk",     "silly",    "silver",   "similar",
    "simple",   "since",    "sing",     "siren",    "sister",   "situate",  "six",      "size",
    "skate",    "sketch",   "ski",      "skill",    "skin",     "skirt",    "skull",    "slab",
    "slam",     "sleep",    "slender",  "slice",    "slide",    "slight",   "slim",     "slogan",
    "slot",     "slow",     "slush",    "small",    "smart",    "smile",    "smoke",    "smooth",
    "snack",    "snake",    "snap",     "sniff",    "snow",     "soap",     "soccer",   "social",
    "sock",     "soda",     "soft",     "solar",    "soldier",  "solid",    "solution", "solve",
    "someone",  "song",     "soon",     "sorry",    "sort",     "soul",     "sound",    "soup",
    "source",   "south",    "space",    "spare",    "spatial",  "spawn",    "speak",    "special",
    "speed",    "spell",    "spend",    "sphere",   "spice",    "spider",   "spike",    "spin",
    "spirit",   "split",    "spoil",    "sponsor",  "spoon",    "sport",    "spot",     "spray",
    "spread",   "spring",   "spy",      "square",   "squeeze",  "squirrel", "stable",   "stadium",
    "staff",    "stage",    "stairs",   "stamp",    "stand",    "start",    "state",    "stay",
    "steak",    "steel",    "stem",     "step",     "stereo",   "stick",    "still",    "sting",
    "stock",    "stomach",  "stone",    "stool",    "story",    "stove",    "strategy", "street",
    "strike",   "strong",   "struggle", "student",  "stuff",    "stumble",  "style",    "subject",
    "submit",   "subway",   "success",  "such",     "sudden",   "suffer",   "sugar",    "suggest",
    "suit",     "summer",   "sun",      "sunny",    "sunset",   "super",    "supply",   "supreme",
    "sure",     "surface",  "surge",    "surprise", "surround", "survey",   "suspect",  "sustain",
    "swallow",  "swamp",    "swap",     "swarm",    "swear",    "sweet",    "swift",    "swim",
    "swing",    "switch",   "sword",    "symbol",   "symptom",  "syrup",    "system",   "table",
    "tackle",   "tag",      "tail",     "talent",   "talk",     "tank",     "tape",     "target",
    "task",     "taste",    "tattoo",   "taxi",     "teach",    "team",     "tell",     "ten",
    "tenant",   "tennis",   "tent",     "term",     "test",     "text",     "thank",    "that",
    "theme",    "then",     "theory",   "there",    "they",     "thing",    "this",     "thought",
    "three",    "thrive",   "throw",    "thumb",    "thunder",  "ticket",   "tide",     "tiger",
    "tilt",     "timber",   "time",     "tiny",     "tip",      "tired",    "tissue",   "title",
    "toast",    "tobacco",  "today",    "toddler",  "toe",      "together", "toilet",   "token",
    "tomato",   "tomorrow", "tone",     "tongue",   "tonight",  "tool",     "tooth",    "top",
    "topic",    "topple",   "torch",    "tornado",  "tortoise", "toss",     "total",    "tourist",
    "toward",   "tower",    "town",     "toy",      "track",    "trade",    "traffic",  "tragic",
    "train",    "transfer", "trap",     "trash",    "travel",   "tray",     "treat",    "tree",
    "trend",    "trial",    "tribe",    "trick",    "trigger",  "trim",     "trip",     "trophy",
    "trouble",  "truck",    "true",     "truly",    "trumpet",  "trust",    "truth",    "try",
    "tube",     "tuition",  "tumble",   "tuna",     "tunnel",   "turkey",   "turn",     "turtle",
    "twelve",   "twenty",   "twice",    "twin",     "twist",    "two",      "type",     "typical",
    "ugly",     "umbrella", "unable",   "unaware",  "uncle",    "uncover",  "under",    "undo",
    "unfair",   "unfold",   "unhappy",  "uniform",  "unique",   "unit",     "universe", "unknown",
    "unlock",   "until",    "unusual",  "unveil",   "update",   "upgrade",  "uphold",   "upon",
    "upper",    "upset",    "urban",    "urge",     "usage",    "use",      "used",     "useful",
    "useless",  "usual",    "utility",  "vacant",   "vacuum",   "vague",    "valid",    "valley",
    "valve",    "van",      "vanish",   "vapor",    "various",  "vast",     "vault",    "vehicle",
    "velvet",   "vendor",   "venture",  "venue",    "verb",     "verify",   "version",  "very",
    "vessel",   "veteran",  "viable",   "vibrant",  "vicious",  "victory",  "video",    "view",
    "village",  "vintage",  "violin",   "virtual",  "virus",    "visa",     "visit",    "visual",
    "vital",    "vivid",    "vocal",    "voice",    "void",     "volcano",  "volume",   "vote",
    "voyage",   "wage",     "wagon",    "wait",     "walk",     "wall",     "walnut",   "want",
    "warfare",  "warm",     "warrior",  "wash",     "wasp",     "waste",    "water",    "wave",
    "way",      "wealth",   "weapon",   "wear",     "weasel",   "weather",  "web",      "wedding",
    "weekend",  "weird",    "welcome",  "west",     "wet",      "whale",    "what",     "wheat",
    "wheel",    "when",     "where",    "whip",     "whisper",  "wide",     "width",    "wife",
    "wild",     "will",     "win",      "window",   "wine",     "wing",     "wink",     "winner",
    "winter",   "wire",     "wisdom",   "wise",     "wish",     "witness",  "wolf",     "woman",
    "wonder",   "wood",     "wool",     "word",     "work",     "world",    "worry",    "worth",
    "wrap",     "wreck",    "wrestle",  "wrist",    "write",    "wrong",    "yard",     "year",
    "yellow",   "you",      "young",    "youth",    "zebra",    "zero",     "zone",     "zoo",
)
# fmt: on

# The reverse mapping of the BIP39 wordlist.
# Used by the `bip39_decode_phrase` function to map the given words back to their 0-based indices.
BIP39_WORD_INDICES: dict[str, int] = {word: i for i, word in enumerate(BIP39_WORDLIST)}


def bip39_encode_bytes(sequence: bytes) -> str:
    """Converts a given sequence of bytes into a BIP39 phrase. This implementation only covers the English
    BIP39 wordlist as other wordlist are often poorly supported by other software and hardware devices.
    """
    num_bits_entropy = len(sequence) * 8
    num_bits_checksum = num_bits_entropy // 32
    num_words = (num_bits_entropy + num_bits_checksum) // 11
    if num_bits_entropy not in {128, 160, 192, 224, 256}:
        raise ValueError(
            "Invalid number of bytes provided, BIP39 phrases are only specified for 128, 160, 192, 224, or 256 bits."
        )

    # Compute the checksum as the first bits of the sha256 hash of the data.
    # As the checksum has at most 8 bits, we can directly access the first byte of the hash.
    checksum = hashlib.sha256(sequence).digest()[0] >> (8 - num_bits_checksum)

    # Covert the entropy to a number of easier handling of the 11-bit parts and append the checksum.
    entropy_and_checksum = (int.from_bytes(sequence, byteorder="big") << num_bits_checksum) | checksum

    # Convert each 11 bit chunk into a word.
    remaining_data = entropy_and_checksum
    words: list[str] = []
    for _ in range(num_words):
        words.append(BIP39_WORDLIST[remaining_data & 0b111_1111_1111])
        remaining_data >>= 11

    # As we started with the conversion progress with the rightmost bits of `entropy_and_checksum` the list of words
    # needs to be reversed before we can join and return the final phrase.
    words.reverse()
    return " ".join(words)


def bip39_decode_phrase(phrase: str) -> bytes:
    """Converts a given BIP39 phrase to a sequence of bytes. The (weak) integrated checksum is verified and a
    `ValueError` is raised in case the phrase is invalid. This implementation only covers the English BIP39
    wordlist as other wordlist are often poorly supported by other software and hardware devices.
    """
    if not all(c in " abcdefghijklmnopqrstuvwxyz" for c in phrase):
        raise ValueError(f"phrase contains an invalid character(s)")

    words = phrase.split()
    num_bits_entropy = bip39_get_bit_length(len(words))
    num_bits_checksum = num_bits_entropy // 32

    invalid_words = []
    bits = 0
    for word in words:
        bits <<= 11
        try:
            bits |= BIP39_WORD_INDICES[word]
        except KeyError:
            if word not in invalid_words:
                invalid_words.append(word)

    if len(invalid_words) == 1:
        raise ValueError(f"the word {invalid_words[0]!r} is not part of the BIP39 wordlist")
    if len(invalid_words) > 1:
        raise ValueError(
            f"the words {', '.join(repr(w) for w in invalid_words[:1])}, "
            f"and {invalid_words[-1]!r} are not part of the BIP39 wordlist"
        )

    checksum = bits & (2**num_bits_checksum - 1)
    bits >>= num_bits_checksum
    data = bits.to_bytes(num_bits_entropy // 8, byteorder="big")

    checksum_for_verification = hashlib.sha256(data).digest()[0] >> (8 - num_bits_checksum)
    if checksum != checksum_for_verification:
        raise ValueError("checksum verification failed")

    return data


def bip39_phrase_to_seed(phrase: str, passphrase: str = "") -> bytes:
    """Converts a given BIP39 phrase to the corresponding 512-bit seed as specified in BIP39.
    Included for referecne only. This code it not used for the secret sharing implementation.
    """
    # Try to decode the given phrase.
    # This raises an exception in case an invalid phrase is passed here.
    phrase_bytes = bip39_decode_phrase(phrase)

    # Convert the result (bytes) back to a phrase (str) to obtain a normalized form of the phrase.
    normalized_phrase = bip39_encode_bytes(phrase_bytes)

    passphrase = "mnemonic" + unicodedata.normalize("NFKD", passphrase)
    return hashlib.pbkdf2_hmac("sha512", normalized_phrase.encode(), passphrase.encode(), iterations=2048)


def bip39_get_bit_length(num_words: int) -> int:
    """Returns the number of entropy bits in a BIP39 phrase with the given number of words.
    Raises a `ValueError` if the given number of words is invalid.
    """
    if bit_length := {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}.get(num_words):
        return bit_length

    raise ValueError("invalid phrase length, BIP39 phrases are only specified for 12, 15, 18, 21, or 24 words")


def bip39_verify_phrase(phrase: str, strict: bool = False) -> bool:
    """Checks if a given (english) BIP39 phrase can successfully be decoded. Returns True on success, false otherwise.
    If strict is set to True, a single whitespace is enforced for word seperation.
    """
    try:
        phrase_bytes = bip39_decode_phrase(phrase)
        if strict:
            return phrase == bip39_encode_bytes(phrase_bytes)
        return True
    except Exception:
        return False


def bip39_encode_share(share_index: int, share_value: bytes) -> str:
    """Encodes a given share, i.e. a (index, value) tuple, as index-prefixed BIP39 string."""
    if not 1 <= share_index <= 255:
        raise ValueError("share index invalid")
    return f"{share_index}: {bip39_encode_bytes(share_value)}"


def bip39_decode_share(share: str) -> tuple[int, bytes]:
    """Decode a share, given as index-prefixed BIP39 string, into its share index and share value."""
    parts = share.split(":")
    if len(parts) != 2:
        index_note = "." if any(c in "0123456789" for c in share) else ", index missing?"
        raise ValueError(f"invalid share format{index_note}")

    try:
        share_index = int(parts[0])
    except ValueError:
        raise ValueError(f"share index invalid")

    if not (1 <= share_index <= 255):
        raise ValueError(f"share index {share_index} out of the allowed range of {{1, 2, ..., 255}}")

    share_value = bip39_decode_phrase(parts[1])
    return share_index, share_value


def bip39_verify_share(share: str, strict: bool = False) -> bool:
    """Checks if a given (english) BIP39 phrase can successfully be decoded. Returns True on success, false otherwise.
    If strict is set to True, a single whitespace is enforced for word seperation.
    """
    try:
        share_index, share_value = bip39_decode_share(share)
        if strict:
            return share == bip39_encode_share(share_index, share_value)
        return True
    except Exception:
        return False


########################################################################################################################
### Secret sharing functionality #######################################################################################
########################################################################################################################


def share_bytes(secret: bytes, num_shares: int, threshold: int, session: str | None = None) -> list[tuple[int, bytes]]:
    """Sets up a new secret sharing polynomials for sharing the given secret value, and then uses these polynomials to
    share the secret. The sharing process is performed on a byte-per-byte basis. The polynomial for sharing byte `b` of
    the secret, is given by the values of `coefficients[0][b]` to `coefficients[t - 1][b]`, where `t` is an
    abbreviation for the secret sharing threshold.
    """
    coefficients = setup_coefficients(secret, threshold, session)
    shares = [(i, bytearray(len(secret))) for i in range(1, num_shares + 1)]
    for byte_index in range(len(secret)):
        cs = [coefficients[k][byte_index] for k in range(threshold)]
        for share_index, share_value in shares:
            share_value[byte_index] = gf256_evaluate_polynomial(cs, share_index)
    return [(share_index, bytes(share_value)) for share_index, share_value in shares]


def recover_bytes(shares: list[tuple[int, bytes]]) -> bytes:
    """Recovers a secret from the given shares. This is a raw recovery using Lagrange interpolation, which does
    recover the correct secret if a sufficient number of correct shares are provided. If one or more invalid shares
    are provided an incorrect secret is recovered.
    """
    share_len = len(shares[0][1])
    secret = bytearray(share_len)

    for xi, yi in shares:
        lagrange_base = 1
        for xj, _ in shares:
            if xi != xj:
                lagrange_base = gf256_multiply(lagrange_base, gf256_multiply(xj, gf256_inverse(xj ^ xi)))
        for byte_index in range(share_len):
            secret[byte_index] ^= gf256_multiply(yi[byte_index], lagrange_base)

    return bytes(secret)


def setup_coefficients(secret: bytes, threshold: int, session: str | None = None) -> list[bytes]:
    """Sets up the coefficients for secret sharing the given secret. The secret itself forms coefficient zero,
    whereas the other coefficients are picked randomly (default) or are derived from the given secret if a value for
    session_id is passed.
    """
    coefficients = [secret]

    for j in range(1, threshold):
        # Deterministically derive coefficient using the underlying secret (and additional information).
        # This provides added protection in case the internal random number generator is bad.
        coefficient = hmac.new(
            key=secret,
            msg=b"secret-sharing-coefficient" + bytes([threshold, j]) + (session or "").encode(),
            digestmod=hashlib.sha256,
        ).digest()[: len(secret)]

        # Randomize the coefficient in case the derivation seed is not providied (default).
        if session is None:
            random_bytes = secrets.token_bytes(len(secret))
            coefficient = xor_bytes(coefficient, random_bytes)

        coefficients.append(coefficient)

    return coefficients


########################################################################################################################
### GF256 field arithmetics ############################################################################################
########################################################################################################################


def _gf256_multiply(a: int, b: int) -> int:
    """Implements multiplication of `a` times `b` in GF256, i.e.,
    multiplication modulo the AES irreducible polynomial `x**8 + x**4 + x**3 + x + 1`.
    """
    IRREDUCIBLE_POLYNOMIAL = 0b100011011

    product = 0
    while b > 0:
        # add (xor operation) `a` to the product if the last bit of `b` == 1
        product ^= a * (b & 1)

        # shift `a` one bit to the left
        # and perform a modulo reduction if there is an overflow after shifting (a >> 8 == 1)
        a <<= 1
        a ^= (a >> 8) * IRREDUCIBLE_POLYNOMIAL

        # move the next highest bit of `b` bit shifting it down
        b >>= 1

    return product


def gf256_multiply(a: int, b: int) -> int:
    """Implements multiplication of `a` times `b` in GF256, i.e., multiplication modulo the AES irreducible
    polynomial `x**8 + x**4 + x**3 + x + 1`. Faster implementation using a pregenerated lookup table (64KB).
    """
    return GF256_MULTIPLICATION_TABLE[(a << 8) | b]


def gf256_inverse(e: int) -> int:
    """Implements finding the inverse of an GF256 element `e` via a lookup table."""
    if e == 0:
        raise ValueError("Zero has no inverse element!")
    return GF256_INVERSE_LOOKUP_TABLE[e]


def gf256_init_multiplication_table() -> bytes:
    """Initializes the lookup table (256*256 elements) for quickly multiplying elements in GF256.
    The product `a * b` is computed by accessing the lookup table at index `(a << 8) | b`.
    """
    return bytes(0 if (i == 0 or j == 0) else _gf256_multiply(i, j) for i in range(256) for j in range(256))


def gf256_init_inverse_lookup_table() -> bytes:
    """Initializes the lookup table (256 elements) for quickly finding inverse elements in GF256."""
    table = [0] * 256
    for e in range(1, 256):
        for i in range(e, 256):
            if gf256_multiply(e, i) == 1:
                table[e] = i
                table[i] = e
    return bytes(table)


def verify_gf256_mul_table(table: bytes) -> bytes:
    """Verify the correct creation of the gf256 multiplication lookup table."""
    digest = hashlib.sha256(table).hexdigest()
    assert digest == "14a1e7e77ca8a30b5bb53e6310748ce0498eb9e04ab78a44dbefb6ebfac8a84b"
    return table


def verify_gf256_inv_table(table: bytes) -> bytes:
    """Verify the correct creation of the gf256 inverse lookup table."""
    digest = hashlib.sha256(table).hexdigest()
    assert digest == "a0b6126fef317bb998059c2fca3dddb40f2422e049866c3df87f1fde4e70a132"
    return table


GF256_MULTIPLICATION_TABLE: bytes = verify_gf256_mul_table(gf256_init_multiplication_table())
GF256_INVERSE_LOOKUP_TABLE: bytes = verify_gf256_inv_table(gf256_init_inverse_lookup_table())


def gf256_evaluate_polynomial(coefficients: list[int], x: int) -> int:
    """Evaluates the `t+1`-degree polynomial given its `t` coeffcients over GF256:
    c[0] + c[1] x + c[2] x^2 + ... + c[t-1] x^{t-1}
    """
    t = len(coefficients)
    if t == 0:
        return 0

    # add term c[0] to result
    result = coefficients[0]

    # add terms c[1] x + ... + c[t-2] x^{t-2} to `result`
    # xk is a helper variable holding the value value x^k
    xk = x
    for k in range(1, t - 1):
        result ^= gf256_multiply(coefficients[k], xk)
        xk = gf256_multiply(xk, x)

    # add the last term c[t-1] to `result` (ensure t[0] is not added twice)
    if t - 1 > 0:
        result ^= gf256_multiply(coefficients[t - 1], xk)

    return result


########################################################################################################################
### Helper functions. ##################################################################################################
########################################################################################################################

CARDS = tuple(f"{v}{s}" for s, v in itertools.product("CDHS", "A23456789TJQK"))


def xor_bytes(ax: bytes, bx: bytes) -> bytes:
    """Compute the binary xor operation on two bytes objects of equal length."""
    if len(ax) != len(bx):
        raise ValueError("Cannot xor two bytes string of unequal length.")
    return bytes(a ^ b for a, b in zip(ax, bx))


def convert_card_sequence_to_binary_string(cards: list[str]) -> str:
    binary_values: list[str] = []
    for card in cards:
        index = CARDS.index(card)
        if index < 32:
            binary_values.append(f"{index:05b}")
            continue
        index -= 32
        if index < 16:
            binary_values.append(f"{index:04b}")
            continue
        index -= 16
        binary_values.append(f"{index:02b}")
    return "".join(binary_values)


def convert_dice_rolls_to_binary_string(dice_rolls: list[int]) -> str:
    t = ["", "01", "10", "11", "0", "1", "00"]
    return "".join(t[r] for r in dice_rolls)


########################################################################################################################
### Command line interface definitions #################################################################################
########################################################################################################################


COMMANDS = {"generate", "share", "recover", "encode", "decode"}

FLAGS_BY_COMMAND: dict[str | None, list[str]] = {
    None: [],
    "generate": ["--deterministic"],
    "share": ["--deterministic"],
    "recover": [],
    "encode": ["--hex", "--dice", "--cards", "--indices"],
    "decode": ["--hex", "--indices"],
}
for flags in FLAGS_BY_COMMAND.values():
    flags.append("-h")
    flags.append("--help")
    flags.append("--quiet")

KEYWORD_ARGS_BY_COMMAND: dict[str | None, list[str]] = {
    None: [],
    "generate": ["--entropy"],
    "share": ["--session"],
    "recover": [],
    "encode": [],
    "decode": [],
}

FLAGS: set[str] = set(itertools.chain.from_iterable(FLAGS_BY_COMMAND.values()))
KEYWORD_ARGS: set[str] = set(itertools.chain.from_iterable(KEYWORD_ARGS_BY_COMMAND.values()))


USAGE = f"""
Usage: %(program)s [options] command [command_args]

BIP39 toolkit version: {VERSION}

The BIP39 toolkit provides a set of commands to generate new BIP39 phrases, share and recover BIP39 phrases using Shamir Secret Sharing, and covert between various entropy formats and BIP39 phrases.

Available commands:
  generate       generate a new BIP39 phrase using the system's CSPRNG
  share          split the given BIP39 phrase into a set of `n` shares such that at least `t` shares are required to recover the original phrase
  recover        recover a BIP39 phrase from a set of at least `t` shares
  encode         convert the given input to the corresponding BIP39 phrase
  decode         convert the given BIP39 phrase to the specified format

Options:
  -h, --help     show this help message and exit, additional information is available for each command
  --quiet        suppress all non-essential output
"""

USAGE_GENERATE = """
Usage: %(program)s generate [options] [num_words]

Generates a new BIP39 phrase of the given length using the system's CSPRNG. Additional entropy for the CSPRNG may be provided by passing the `--entropy` parameter. The `--deterministic` flag may be used to bypass the use of the system's entropy source and deterministically derive the BIP39 phrase from the user-provided entropy instead.

CAUTION: Use of the `--deterministic` flag with user-provided entropy of poor quality will result in the generation of an insecure BIP39 phrase.

Positional arguments:
  num_words          the length the phrase to generate (12, 15, 18, 21 or 24 words, default: 24)

Options:
  -h, --help         show this help message and exit
  --quiet            suppress all non-essential output
  --entropy ENTROPY  an arbitrary string used as additional entropy source for the CSPRNG
  --deterministic    if specified, only the used-provided entropy is used to seed the CSPRNG
"""

USAGE_SHARE = """
Usage: %(program)s share [options] num_shares threshold phrase

Split the given BIP39 phrase into a set of `n` shares such that at least `t` shares are required to recover the original phrase. The `--determinstic` flag may be specified to ensure the re-executing this command for the given phrase and recovery threshold will yield in the same set of shares. In this case, the provided BIP39 phrase and (if specified) the `--session` parameter, used to identify a particular secret sharing instance, are used to seed the system's CSRNG. The --session parameter can only be used in addition to the `--deterministic` flag. Shares from session with a different identifiers are incompatible.

Positional arguments:
  num_shares (n)  the total number of shares to generate (1 <= n <= 255)
  threshold (t)   the minimum number of shares required for recovery (1 <= t <= n)
  phrase          the BIP39 phrase to share, format: "{word 1} {word 2} ... {word 12|15|18|21|24}"

Options:
  -h, --help         show this help message and exit
  --quiet            suppress all non-essential output
  --deterministic    if specified, the shares are generated deterministically
  --session SESSION  an arbitrary string used to identify a particular secret sharing instance
"""

USAGE_RECOVER = """
Usage: %(program)s recover [options] shares

Recovers a previously shared BIP39 phrase from a set of at least `t` shares. Each share is specified the following format: "{index}: {word 1} {word 2} ... {word 12|15|18|21|24}".

Positional arguments:
  shares      the BIP39 shares used to recover the shared secret

Options:
  -h, --help  show this help message and exit
  --quiet     suppress all non-essential output
"""

USAGE_ENCODE = """
Usage: %(program)s encode [options] input

Converts the given input (hex, dice rolls, playing cards, word indices) to the corresponding BIP39 phrase. The --hex, --dice, --cards, or --indices flag is used to specify the input format (default: --hex). Sequences of dice rolls, playing cards, or word indices are passed as single argument seperated using spaces or colons.

Positional arguments:
  input       the input which should be converted into a BIP39 phrase

Options:
  -h, --help  show this help message and exit
  --quiet     suppress all non-essential output
  --hex       input format: a hex string [0-9a-fA-F]
  --dice      input format: a sequence of dice rolls [1-6]+
  --cards     input format: a sequence of playing cards [A2-9TJQK][CDHS]
  --indices   input format: a sequence of words indices [0-2047]

CAUTION: `encode` is an advanced command, using it with user-provided entropy of poor quality will result in the generation of an insecure BIP39 phrase.
"""

USAGE_DECODE = """
Usage: %(program)s encode [options] input

Converts the given BIP39 phrase into a hex string or sequence of word indices. The flag --hex or --indices is used to specify the output format (default: --hex). 

Positional arguments:
  phrase       the phrase which should be converted into a different format

Options:
  -h, --help  show this help message and exit
  --quiet     suppress all non-essential output
  --hex       output format: a hex string [0-9a-fA-F]
  --indices   output format: a sequence of words indices [0-2047]
"""


########################################################################################################################
### Command line interface: command implementations (after input validation) ###########################################
########################################################################################################################


def generate(num_words: int, deterministic: bool = False, entropy: str | None = None) -> str:
    """Main interface function for generates or derives a new BIP39 phrase of the given length."""
    num_bits = bip39_get_bit_length(num_words)
    num_bytes = num_bits // 8

    if entropy is None:
        print_info(
            f"Generating a BIP39 phrase ({num_words} words / {num_bits} bits) using the system's internal "
            f"cryptographically secure random number generator (no additional user-supplied entropy is used)."
        )
        secret = secrets.token_bytes(32)
    else:
        entropy_bytes = hmac.new(key=entropy.encode(), msg=b"BIP39 phrase", digestmod=hashlib.sha256).digest()
        if deterministic:
            print_info(
                f"Deterministically deriving a BIP39 phrase ({num_words} words / {num_bits} bits) from the "
                f"user-supplied entropy."
            )
            print_info(
                "CAUTION: "
                "The security of the generated phrase critically depends on the quality of the provided entropy."
            )
            secret = entropy_bytes
        else:
            print_info(
                f"Generating a BIP39 phrase ({num_words} words / {num_bits} bits) using the system's internal "
                f"cryptographically secure random number generator in combination with the user-supplied entropy."
            )
            secret = xor_bytes(secrets.token_bytes(32), entropy_bytes)

    phrase = bip39_encode_bytes(secret[:num_bytes])
    print_phrase(phrase)
    return phrase


def share(
    phrase: str, num_shares: int, threshold: int, deterministic: bool = False, session: str | None = None
) -> list[str]:
    """Main interface function for secret sharing a BIP39 phrase."""
    secret = bip39_decode_phrase(phrase)
    print_info("BIP39 phrase loaded.")
    print_phrase(phrase)
    print_info()
    print_info(
        f"Set up to generate n={num_shares} secret shares for the given BIP39 phrase, such that "
        f"t={threshold} shares are required to recover the original phrase."
    )
    if deterministic:
        session_info = ""
        if session is None:
            session = ""
        else:
            session_info = (
                f" The session parameter {session!r} is used for deriving the share. To get the same set of shares, "
                f"reshare using the same session parameter.  Using a different (or no) session parameter, resharing "
                f"will yield a different and incompatible set of shares."
            )
        mode = f"deterministic, resharing the same phrase will yield the same set of shares.{session_info}"
    else:
        mode = "randomized, resharing the same phrase will yield a different and incompatible set of shares."

    print_info(f"Sharing mode: {mode}")
    print_info()

    print_info("Running secret sharing procedure...")
    raw_shares = share_bytes(secret, num_shares, threshold, session)
    shares = [bip39_encode_share(share_index, share_value) for share_index, share_value in raw_shares]
    print_info("Shares created.")

    run_selftest(phrase, num_shares, threshold, shares)
    for share in shares:
        print_share(share)
    return shares


def recover(shares: list[str] | tuple[str, ...]) -> str:
    """Main interface function to recover a shared BIP39 phrase from the given list of shares."""
    print_info("BIP39 shares loaded.")
    for share in shares:
        print_share(share)

    print_info()
    print_info("Running share recovery procedure...")

    raw_shares = [bip39_decode_share(share) for share in shares]
    secret = recover_bytes(raw_shares)
    phrase = bip39_encode_bytes(secret)

    print_info("BIP39 phrase recovered.")
    print_phrase(phrase)
    return phrase


def encode(
    data: str | list[int] | list[str], input_format: typing.Literal["hex", "dice", "cards", "indices"] = "hex"
) -> str:
    """Main interface function to convert (encode) the given input into the corresponding BIP39 phrase."""
    print_info(f"Input loaded: {data!r}")
    print_info()

    if input_format == "hex":
        print_info("Converting the given hexstring to the corresponding BIP39 phrase.")
        phrase = bip39_encode_bytes(bytes.fromhex(data))  # type: ignore

    elif input_format == "indices":
        print_info("Converting the given list of word indices to the corresponding BIP39 phrase.")
        phrase = " ".join(BIP39_WORDLIST[i] for i in data)  # type: ignore

    elif input_format == "dice" or input_format == "cards":
        if input_format == "dice":
            print_info("Converting the given sequence of dice rolls to the corresponding BIP39 phrase.")
            binary_entropy = convert_dice_rolls_to_binary_string(data)  # type: ignore
        else:
            print_info("Converting the given sequence of playing cards to the corresponding BIP39 phrase.")
            binary_entropy = convert_card_sequence_to_binary_string(data)  # type: ignore

        if len(binary_entropy) < 128:
            raise AppExecutionError(
                f"The provided input only contains {len(binary_entropy)} bits of entropy, "
                "at least 128 bits are required."
            )

        trimmed_bit_length = ([b for b in BIP39_BIT_LENGTHS if len(binary_entropy) >= b])[-1]
        if trimmed_bit_length != len(binary_entropy):
            print_info(f"Note: input of length: {len(binary_entropy)} bits, left-trimmed to {trimmed_bit_length} bits.")
            binary_entropy = binary_entropy[:trimmed_bit_length]

        phrase = bip39_encode_bytes(int(binary_entropy, 2).to_bytes(trimmed_bit_length // 8, byteorder="big"))

    else:
        assert False, "Implementation error."

    print_info("BIP39 phrase created.")
    print_phrase(phrase)
    return phrase


def decode(phrase: str, output_format: typing.Literal["hex", "indices"] = "hex") -> str | list[int]:
    """Main interface function to convert (decode) a BIP39 phrase into the specified format."""
    print_info("BIP39 phrase loaded.")
    print_phrase(phrase)
    print_info()

    if output_format == "hex":
        print_info("Converting the given BIP39 phrase to a hexstring.")
        result = bip39_decode_phrase(phrase).hex()
        print_info("Decoding completed.")
        print_info()
        print_info(f'"{result}"')

    elif output_format == "indices":
        print_info("Converting the given BIP39 phrase to a list of word indices.")
        result = [BIP39_WORD_INDICES[w] for w in phrase.split()]
        print_info("Decoding completed.")
        print_info()
        print_info('"' + ", ".join(str(i) for i in result) + '"')

    else:
        assert False, "Implementation error."

    return result


def run_selftest(phrase: str, num_shares: int, threshold: int, shares: list[str], timeout: float = 10.0) -> None:
    """Implements a selftest which can be run after sharing a phrase to ensure that the secret can indeed be
    recovered. This selftest is expected to always succeed and is provided as additional safeguard against potential
    implementation errors. For a low number of possible combinations (~12 shares), all combinations can be checked
    within a few seconds. For a large number of possible combinations, this function ensures that each share is
    checked at least in one combination, and tests random combinations of shares until the specified timeout (given
    in seconds) elapses.
    """
    # Compute the total number of possible combinations when picking at least t shares of the the provided ones.
    n = num_shares
    t = threshold
    num_combinations = sum(math.comb(n, k) for k in range(t, n + 1))

    print_info()
    print_info(f"Executing selftest...")

    # Keep track of time to abort the selftest after a timeout.
    t_start = time.time()
    t_end = t_start + timeout
    ctr = 0
    for i, k in enumerate(reversed(range(t, n + 1))):
        for shares_for_recovery in itertools.combinations(shares, k):
            with quiet_mode():
                recovered_phrase = recover(shares_for_recovery)
            if phrase != recovered_phrase:
                print_info()
                raise AppExecutionError(
                    "Selftest failed. Something went wrong during the secret sharing process. "
                    "The shared phrase is not recoverable with at least one combination of the provided shares."
                )
            ctr += 1

            # Abort after a certain number of times, but ensure that all shares have been checked (i >= 2 condition).
            if i >= 2 and time.time() > t_end:
                print_info(
                    f"Selftest successful "
                    f"(stopped after {t_end - t_start:.1f} seconds, "
                    f"{ctr} combinations checked, "
                    f"each share checked at least once)."
                )
                return
    else:
        assert ctr == num_combinations
        print_info(f"Selftest successful (all {num_combinations} combinations checked).")


########################################################################################################################
### Command line interface: input validation, usage, and error messages ################################################
########################################################################################################################


argument_errors: AppArgumentError | None = None


class AppExecutionError(Exception):
    """Main error class raised during command execution."""


class AppArgumentError(Exception):
    """Main class to collect (and eventually raise) multiple application errors."""

    @property
    def num_errors(self) -> int:
        return len(self.messages)

    def __init__(self) -> None:
        super().__init__()
        self.messages = []

    def append(self, msg: str) -> None:
        self.messages.append(msg)


def error(msg: str) -> None:
    """Add the given message to the global error object."""
    assert argument_errors is not None, "The `argument_errors` object must be initialized at this point."
    argument_errors.append(msg)


def error_if_non_empty(prefix: str, values: typing.Sequence) -> None:
    """If the given sequence is non-empty, add a new error to global error object, but do not raise the error
    immediately.
    """
    if len(values) == 1:
        prefix = prefix[:-1]
    if len(values) >= 1:
        error(prefix + ": " + ", ".join(repr(k) for k in values))


def print_and_raise_errors(
    command: str | None, error: AppArgumentError | AppExecutionError, do_raise: bool
) -> typing.Literal[1]:
    if isinstance(error, AppArgumentError):
        messages = error.messages
    elif isinstance(error, AppExecutionError):
        messages = [str(error)]
    else:
        assert False, "Implementation error."

    line_width = get_terminal_width()
    for message in messages:
        prefix = "ERROR: " if command is None else f"ERROR ({command}): "
        for line in textwrap.wrap(f"{prefix}{message}", line_width, subsequent_indent=" " * len(prefix)):
            print(line, file=sys.stderr)

    if do_raise:
        raise error
    return 1


def usage(program: str, command: str | None = None) -> None:
    msg: str = USAGE
    if command:
        msg = globals()[f"USAGE_{command.upper()}"]
    msg = msg % {"program": program}

    line_width = get_terminal_width()
    lines = msg.strip().splitlines()
    for line in lines:
        matches = list(re.finditer(r" {2,}", line))
        if len(matches) < 2:
            print("\n".join(textwrap.wrap(line, line_width)))
        else:
            print("\n".join(textwrap.wrap(line, line_width, subsequent_indent=" " * matches[-1].end())))


def get_terminal_width() -> int:
    return shutil.get_terminal_size().columns


class quiet_mode:
    """Context manager to set `quiet mode` to the given value and restore its previous value after the context manager
    exits.
    """

    is_enabled: typing.ClassVar[bool] = False

    def __init__(self, enable: bool = True) -> None:
        self.value = enable

    def __enter__(self):
        self.restore_value = quiet_mode.is_enabled
        quiet_mode.is_enabled = self.value

    def __exit__(self, type, value, traceback):
        quiet_mode.is_enabled = self.restore_value


def print_info(msg: str | None = None) -> None:
    if quiet_mode.is_enabled:
        return

    if msg is None:
        print()
        return

    line_width = get_terminal_width()
    for line in textwrap.wrap(msg, line_width):
        print(line)


def print_phrase(phrase: str) -> None:
    if quiet_mode.is_enabled:
        return

    sha256_hash = hashlib.sha256(phrase.encode()).hexdigest()
    print()
    print(f'"{phrase}"')
    print(f"(SHA2-256 hash: {sha256_hash})")


def print_result(value: str | list[str] | list[int]) -> None:
    """Print the result of any main command in minimal form if quiet mode is enabled. No line wrapping is applied."""
    if not quiet_mode.is_enabled:
        return

    if isinstance(value, str):
        lines = [value]
    elif isinstance(value, list) and isinstance(value[0], str):
        lines = value
    elif isinstance(value, list) and isinstance(value[0], int):
        lines = [", ".join(str(v) for v in value)]
    else:
        assert False, "Implementation error."

    for line in lines:
        print(f'"{line}"')


def print_share(share: str) -> None:
    print_phrase(share)


def parse_args(args: list[str]) -> tuple[str | None, list[str], dict[str, str], set[str]]:
    """Parse the given command line arguments. Exits the application and prints error message(s) if invalid arguments
    are provided.
    """
    args, keyword_args, flags, invalid_args = split_args(args)
    command = None
    if args:
        if args[0] in COMMANDS:
            command, *args = args
        else:
            error(f"Invalid command: {args[0]!r}")

    unexpected_flags = [f for f in flags if f not in FLAGS_BY_COMMAND[command]]
    unexpected_keyword_args = [k for k in keyword_args if k not in KEYWORD_ARGS_BY_COMMAND[command]]
    keyword_args_with_missing_values = [
        name
        for name, values in keyword_args.items()
        if name not in unexpected_keyword_args and any(v is None for v in values)
    ]
    keyword_args_with_multiple_values = [
        name for name, value in keyword_args.items() if name not in unexpected_keyword_args and len(value) > 1
    ]

    error_if_non_empty("Invalid arguments", invalid_args)
    error_if_non_empty("Unexpected arguments", unexpected_keyword_args)
    error_if_non_empty("Unexpected flags", unexpected_flags)
    error_if_non_empty("Missing value for arguments", keyword_args_with_missing_values)
    error_if_non_empty("Multiple values for arguments", keyword_args_with_multiple_values)

    # At this point, we extract one value per keyword argument
    # If there are multiple values an error was reported above.
    keyword_args = {name: values[0] for name, values in keyword_args.items()}
    return command, args, keyword_args, flags


def split_args(args: list[str]) -> tuple[list[str], dict[str, list[str]], set[str], list[str]]:
    """Splits a list of command line arguments into positional arguments, keyword argument, flags, and a list of invalid
    arguments. Ensures that the names of keyword arguments and flags are valid.
    """
    positional_args = []
    keyword_args = collections.defaultdict(list)
    flags = set()
    invalid_args = []

    i = 0
    while i < len(args):
        if args[i].startswith("-"):
            if args[i] in FLAGS:
                flags.add(args[i])
            elif args[i] in KEYWORD_ARGS:
                if i == len(args) - 1 or args[i + 1] in FLAGS or args[i + 1] in KEYWORD_ARGS:
                    keyword_args[args[i]].append(None)
                else:
                    keyword_args[args[i]].append(args[i + 1])
                    i += 1
            else:
                invalid_args.append(args[i])
        else:
            positional_args.append(args[i])
        i += 1

    return positional_args, keyword_args, flags, invalid_args


def parse_integer(arg_name: str, arg_value: str, low: int = 1, high: int = 255) -> int:
    """Verifies that the given argument is an integer from given range (both bounds inclusive). Returns the parsed value
    on success. Otherwise the error handler is called and 0 is returned.
    """
    value = 0
    try:
        value = int(arg_value)
        if not (low <= value <= high):
            raise ValueError
    except ValueError:
        error(f"Invalid value {arg_value!r} for argument `{arg_name}` (a value from {low} to {high} is required).")
    return value


def parse_phrase(phrase: str) -> str:
    """Verifies the validity of the given phrase and returns it in normalized form if successful. Otherwise the error
    handler is called and a empty phrase is returned.
    """
    normalized_phrase = ""
    try:
        secret = bip39_decode_phrase(phrase)
        normalized_phrase = bip39_encode_bytes(secret)
    except ValueError as e:
        error(f"Invalid value {phrase!r} for argument `phrase` ({e}).")
    return normalized_phrase


def parse_share(share: str) -> str:
    """Verifies the validity of the given phrase and returns it in normalized form if successful. Otherwise the error
    handler is called and a empty share is returned.
    """
    normalized_share = ""
    try:
        index, value = bip39_decode_share(share)
        normalized_share = bip39_encode_share(index, value)
    except ValueError as e:
        error(f"Invalid share {share!r} provided ({e}).")
    return normalized_share


def parse_hex_string(arg: str) -> str:
    """Verifies that the given input is a valid hexstring of allowed length and returns it in normalized form if
    successful. Otherwise the error handler is called and a empty string is returned.
    """
    normalized_arg = re.sub(r"[ ,-]", "", arg).lower()
    is_of_valid_length = len(normalized_arg) in {l // 4 for l in BIP39_BIT_LENGTHS}
    is_hex = re.fullmatch(r"[0-9a-f]+", normalized_arg)

    if is_of_valid_length and is_hex:
        return normalized_arg

    error(
        f"Invalid value {arg!r} provided for the argument `input` "
        f"(a hexstring with a length of 128, 160, 192, 224, or 256 bits is required)."
    )
    return ""


def parse_dice_rolls(arg: str) -> list[int]:
    """Verifies that the given input is a valid sequence of dice rolls returns it as list of integers if successful.
    Otherwise the error handler is called and a empty list is returned.
    """
    normalized_arg = re.sub(r"[ ,-]", "", arg)
    if re.fullmatch(r"[1-6]*", normalized_arg):
        return [int(roll) for roll in normalized_arg]
    error(f"Invalid value {arg!r} provided for the argument `input` (a sequence of dice rolls [1-6]+ is required).")
    return []


def parse_cards(arg: str) -> list[str]:
    """Verifies that the given input is a valid sequence of cards rolls returns it as list of cards if successful.
    Otherwise the error handler is called and a empty list is returned.
    """
    normalized_arg = re.sub(r"[ ,-]", "", arg).upper()
    cards = [normalized_arg[i : i + 2] for i in range(0, len(normalized_arg), 2)]
    invalid_cards = []
    for card in cards:
        if card not in CARDS and cards not in invalid_cards:
            invalid_cards.append(card)

    if invalid_cards:
        error(
            "Invalid value {arg!r} provided for the argument `input` "
            f"(the following values are not valid cards: {', '.join(invalid_cards)})."
        )
        return []
    return cards


def parse_indices(arg: str) -> list[int]:
    """Verifies that the given input is a valid sequence of word indices of allowed length and returns it as list of
    integers if successful. Otherwise the error handler is called and a empty list is returned.
    """
    parts = re.split(r"[ ,-]+", arg)
    indices = []
    for part in parts:
        try:
            value = int(part)
            if 0 <= value <= 2047:
                indices.append(value)
        except ValueError:
            pass

    if len(parts) in BIP39_NUM_WORDS and len(parts) == len(indices):
        return indices

    extra_info = "a sequence of 12, 15, 18, 21, or 24 word indices from the range [0-2047] is required"
    if len(parts) not in BIP39_NUM_WORDS:
        extra_info = (
            f"the provided sequence is of length {len(parts)}; a sequence of 12, 15, 18, 21, or 24 indices is required"
        )
    if len(parts) != len(indices):
        extra_info = "the sequence contains invalid indices; all indices must be from the range [0-2047]"

    error(f"Invalid value {arg!r} provided for the argument `input` ({extra_info})")
    return []


def parse_generate_args(args: list[str], keywords_args: dict[str, str], flags: set[str]) -> dict:
    """Main input validation function for the `generate` command."""
    num_words = 24
    if args:
        if args[0] in {"12", "15", "18", "21", "24"}:
            num_words = int(args[0])
        else:
            error(f"Invalid value {args[0]!r} for argument `num_words` (choose from {{12, 15, 18, 21, 24}}).")
    if len(args) > 1:
        error(f"Unexpected positional argument(s): {', '.join(repr(f) for f in args[1:])}")

    deterministic = "--deterministic" in flags
    entropy = keywords_args.get("--entropy")
    if deterministic and entropy is None:
        error("The use of the `--deterministic` flag requires the argument `--entropy` to be specified.")

    return {"num_words": num_words, "deterministic": deterministic, "entropy": entropy}


def parse_share_args(args: list[str], keywords_args: dict[str, str], flags: set[str]) -> dict:
    """Main input validation function for the `share` command."""
    num_shares = 0
    threshold = 0
    phrase = ""
    if len(args) == 3:
        num_shares = parse_integer("num_shares", args[0])
        threshold = parse_integer("threshold", args[1])
        phrase = parse_phrase(args[2])
    else:
        error(
            "Invalid number of positional arguments, "
            "exactly three arguments (`num_shares`, `threshold`, and `phrase`) expected."
        )

    threshold, num_shares = sorted((threshold, num_shares))
    deterministic = "--deterministic" in flags
    session = keywords_args.get("--session")
    if session is not None and not deterministic:
        error("The use of the `--session` argument the flag `--deterministic` to be specified.")

    return {
        "num_shares": num_shares,
        "threshold": threshold,
        "phrase": phrase,
        "deterministic": deterministic,
        "session": session,
    }


def parse_recover_args(args: list[str], keywords_args: dict[str, str], flags: set[str]) -> dict:
    """Main input validation function for the `recover` command."""
    shares = [parse_share(arg) for arg in args]
    indices = []
    duplicate_indices = []
    share_lengths = set()
    for share in shares:
        try:
            parts = share.split(":")
            index = int(parts[0])
            length = len(parts[1].split())
            if 1 <= index <= 255:
                if index in indices:
                    if index not in duplicate_indices:
                        duplicate_indices.append(index)
                else:
                    indices.append(index)
                    share_lengths.add(length)
        except Exception:
            pass

    if len(shares) == 0:
        error("No shares specified.")
    if duplicate_indices:
        error(f"Shares with duplicate indices ({', '.join(repr(i) for i in duplicate_indices)}) detected.")
    if len(share_lengths) >= 2:
        error(f"Inconsistent share length, all shares must contain the same number of words.")

    return {"shares": shares}


def parse_encode_args(args: list[str], keywords_args: dict[str, str], flags: set[str]) -> dict:
    """Main input validation function for the `encode` command."""
    input_format = "hex"
    if len(flags) >= 1:
        input_format = next(iter(flags))[2:]
    if len(flags) >= 2:
        error("Multiple input formats specified.")

    data = ""
    if len(args) == 1:
        if input_format == "hex":
            data = parse_hex_string(args[0])
        elif input_format == "dice":
            data = parse_dice_rolls(args[0])
        elif input_format == "cards":
            data = parse_cards(args[0])
        elif input_format == "indices":
            data = parse_indices(args[0])
        else:
            assert False, "Implementation error."
    else:
        error("Invalid number of positional arguments, exactly one argument (`input`) expected.")

    return {"data": data, "input_format": input_format}


def parse_decode_args(args: list[str], keywords_args: dict[str, str], flags: set[str]) -> dict:
    """Main input validation function for the `decode` command."""
    if len(args) != 1:
        phrase = ""
        error("Invalid number of positional arguments, exactly one argument (`phrase`) expected.")
    else:
        phrase = parse_phrase(args[0])

    output_format = "hex"
    if len(flags) >= 1:
        output_format = next(iter(flags))[2:]
    if len(flags) >= 2:
        error("Multiple output formats specified.")

    return {"phrase": phrase, "output_format": output_format}


def main(_args: list[str] | None = None) -> int:
    """Main entry point of the command line application. Parses the command line argument and calls the appropriate
    functions handling each command.
    """
    global argument_errors
    if _args is None:
        program, *args = sys.argv
    else:
        program, args = "bip39toolkit", list(_args)

    # Perform command independent argument parsing.
    # All errors are collected in the global `argument_errors` object.
    argument_errors = AppArgumentError()
    command, args, keyword_args, flags = parse_args(args)

    # Display a usage message and exit if the `-h` or the `--help` flag was provided.
    if "-h" in flags or "--help" in flags:
        usage(program, command)
        return 0

    # Exit if no command was given.
    # Display error message if same invalid arguments are passed.
    # Otherwise display the usage message.
    if command is None:
        if argument_errors.num_errors:
            return print_and_raise_errors(None, argument_errors, do_raise=(_args is not None))
        else:
            usage(program, command)
            return 0

    # Handle quiet mode for all commands.
    quiet = "--quiet" in flags
    flags.discard("--quiet")

    # Prepare the arguments for the specific command by calling the `parse_{command}_args` function.
    command_args: dict = globals()[f"parse_{command}_args"](args, keyword_args, flags)

    # Error handling: print error messages if called from the command line.
    # If called from tests (when `_args` is set) also raise the collected errors.
    if argument_errors.num_errors > 0:
        return print_and_raise_errors(command, argument_errors, do_raise=(_args is not None))

    # Finally excute the a given command with the parsed arguments dict.
    with quiet_mode(quiet):
        try:
            result = globals()[command](**command_args)
            print_result(result)
            return 0
        except AppExecutionError as execution_error:
            return print_and_raise_errors(command, execution_error, do_raise=(_args is not None))


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
