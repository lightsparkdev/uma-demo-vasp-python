from uma.currency import Currency

USD = "USD"
BRL = "BRL"
PHP = "PHP"
MXN = "MXN"
CAD = "CAD"
SAT = "SAT"

# NOTE: In a real app, these values would be fetched from quote API.
MSATS_PER_UNIT = {
    USD: 22883.56,
    SAT: 1_000.0,
    BRL: 4608.84776960979,
    MXN: 1325.80831017669,
    PHP: 405.404106597774,
    CAD: 16836.0372009,
}

RECEIVER_FEES_MSATS = {
    USD: 2_000,
    SAT: 0,
    BRL: 2_000,
    MXN: 2_000,
    PHP: 2_000,
    CAD: 2_000,
}

DECIMALS_PER_UNIT = {USD: 2, SAT: 0, BRL: 2, MXN: 2, PHP: 2, CAD: 2}

CURRENCIES = {
    USD: Currency(
        code=USD,
        name="US Dollar",
        symbol="$",
        millisatoshi_per_unit=MSATS_PER_UNIT[USD],
        min_sendable=1,
        max_sendable=10_000_000,
        decimals=DECIMALS_PER_UNIT[USD],
    ),
    BRL: Currency(
        code=BRL,
        name="Brazilian Real",
        symbol="R$",
        millisatoshi_per_unit=MSATS_PER_UNIT[BRL],
        min_sendable=1,
        max_sendable=10_000_000,
        decimals=DECIMALS_PER_UNIT[BRL],
    ),
    MXN: Currency(
        code=MXN,
        name="Mexican Peso",
        symbol="MX$",
        millisatoshi_per_unit=MSATS_PER_UNIT[MXN],
        min_sendable=1,
        max_sendable=10_000_000,
        decimals=DECIMALS_PER_UNIT[MXN],
    ),
    PHP: Currency(
        code=PHP,
        name="Philippine Peso",
        symbol="₱",
        millisatoshi_per_unit=MSATS_PER_UNIT[PHP],
        min_sendable=1,
        max_sendable=10_000_000,
        decimals=DECIMALS_PER_UNIT[PHP],
    ),
    CAD: Currency(
        code=CAD,
        name="Canadian Dollar",
        symbol="CA$",
        millisatoshi_per_unit=MSATS_PER_UNIT[CAD],
        min_sendable=1,
        max_sendable=10_000_000,
        decimals=DECIMALS_PER_UNIT[CAD],
    ),
    SAT: Currency(
        code=SAT,
        name="Satoshi",
        symbol="",
        millisatoshi_per_unit=MSATS_PER_UNIT[SAT],
        min_sendable=1,
        max_sendable=10_000_000,
        decimals=DECIMALS_PER_UNIT[SAT],
    ),
}
