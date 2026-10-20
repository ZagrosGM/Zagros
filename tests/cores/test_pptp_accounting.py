from app.cores.drivers.pptp.accounting import PptpAccountingLedger, PptpSession


def test_interim_and_final_are_not_double_counted(tmp_path):
    ledger = PptpAccountingLedger(str(tmp_path / "acct.sqlite3"))
    session = PptpSession(ifname="zgppp0", username="1.alice.pptp",
                          rx_bytes=1000, tx_bytes=2000)
    assert ledger.observe("g1", [session])["1.alice.pptp"] == (1000, 2000)
    session = PptpSession(ifname="zgppp0", username="1.alice.pptp",
                          rx_bytes=1500, tx_bytes=2600)
    assert ledger.observe("g1", [session])["1.alice.pptp"] == (1500, 2600)
    ledger.record_final("g1", "zgppp0", "1.alice.pptp", 1800, 3000)
    assert ledger.totals()["1.alice.pptp"] == (1800, 3000)


def test_reconnect_and_generation_restart_preserve_totals(tmp_path):
    path = str(tmp_path / "acct.sqlite3")
    ledger = PptpAccountingLedger(path)
    ledger.observe("old", [PptpSession(ifname="zgppp0", username="u", rx_bytes=10, tx_bytes=20)])
    # Abrupt old generation: observed bytes remain, stale baseline is discarded.
    ledger.observe("new", [])
    ledger.observe("new", [PptpSession(ifname="zgppp0", username="u", rx_bytes=7, tx_bytes=9)])
    assert PptpAccountingLedger(path).totals()["u"] == (17, 29)


def test_counter_reset_accounts_new_generation_without_subtracting(tmp_path):
    ledger = PptpAccountingLedger(str(tmp_path / "acct.sqlite3"))
    ledger.observe("g", [PptpSession(ifname="zgppp0", username="u", rx_bytes=100, tx_bytes=100)])
    ledger.observe("g", [PptpSession(ifname="zgppp0", username="u", rx_bytes=2, tx_bytes=3)])
    assert ledger.totals()["u"] == (102, 103)
