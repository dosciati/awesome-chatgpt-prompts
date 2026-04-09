import asyncio

from enrich.vendors import LocalOuiLookup


def test_local_oui_lookup() -> None:
    lookup = LocalOuiLookup("src/data/oui_sample.csv")
    result = asyncio.run(lookup.lookup("a4:2b:b0:11:22:33"))
    assert result == "Ubiquiti Inc."
