"""GUI integration tests — simulate user interactions and verify forms, defaults, auto-compute, preview."""

import pytest
import tkinter as tk


@pytest.fixture(scope="session")
def app():
    root = tk.Tk()
    root.withdraw()
    from isis_attack.gui.app import MainWindow
    a = MainWindow()
    yield a
    try:
        a.root.destroy()
    except Exception:
        pass


def test_select_all_13_attacks(app):
    expected = {
        "iih-inject":       ["iface", "hello_interval", "hold_timer", "priority"],
        "adjacency-break":  ["iface", "hold_timer", "priority"],
        "dis-hijack":       ["iface", "priority"],
        "route-inject":     ["iface", "lsp_id", "metric", "network_addr"],
        "max-seq":          ["iface", "lsp_id", "sequence"],
        "purge-lsp":        ["iface", "lsp_id", "remaining_lifetime"],
        "fight-back":       ["iface", "lsp_id", "metric"],
        "overload-bit":     ["iface", "lsp_id", "overload_bit"],
        "flood":            ["iface", "duration", "thread_count"],
        "spf-recalc":       ["iface", "duration", "lsp_change_interval"],
        "db-overflow":      ["iface", "duration", "lsp_count"],
        "mitm":             ["iface", "action"],
        "replay":           ["iface"],
    }
    for name, keys in expected.items():
        app._on_attack_select(name)
        d = app._form.get_config_dict()
        for k in keys:
            assert k in d, f"{name}: missing '{k}' in {list(d.keys())}"


# -- defaults --

def test_max_seq_defaults(app):
    app._on_attack_select("max-seq")
    assert app._form.get_config_dict().get("sequence") == 0xFFFFFFFF


def test_purge_lsp_defaults(app):
    app._on_attack_select("purge-lsp")
    assert app._form.get_config_dict().get("remaining_lifetime") == 0


def test_overload_bit_defaults(app):
    app._on_attack_select("overload-bit")
    assert app._form.get_config_dict().get("overload_bit") is True


def test_dis_hijack_priority(app):
    app._on_attack_select("dis-hijack")
    assert int(app._form.get_config_dict().get("priority", "64")) == 127


# -- auto-compute --

def test_lsp_id_auto_generated(app):
    app._on_attack_select("route-inject")
    lsp = app._form._widgets["lsp_id"].get()
    assert lsp.endswith(".00-00"), f"got {lsp}"
    app._form._widgets["sys_id"].set("AAAA.BBBB.CCCC")
    app.root.update()
    assert "AAAA.BBBB.CCCC" in app._form._widgets["lsp_id"].get()


def test_hold_timer_auto(app):
    app._on_attack_select("iih-inject")
    d = app._form.get_config_dict()
    assert int(d.get("hold_timer", 0)) == int(d.get("hello_interval", 10)) * 3
    app._form._widgets["hello_interval"].set("5")
    app.root.update()
    assert int(app._form._widgets["hold_timer"].get()) == 15


# -- preview --

def test_preview_has_content(app):
    app._on_attack_select("route-inject")
    p = app._form.format_preview()
    assert "ISIS" in p or "Common Header" in p


def test_preview_iih_vs_lsp(app):
    app._on_attack_select("iih-inject")
    assert "IIH" in app._form.format_preview() or "Hello" in app._form.format_preview()
    app._on_attack_select("route-inject")
    assert "LSP" in app._form.format_preview()


# -- routes --

def test_routes_holder(app):
    from isis_attack.gui.config_form import RoutesHolder
    h = RoutesHolder()
    assert h.routes == []
    h.routes = [{"network": "10.0.0.0", "mask": "255.255.255.0", "metric": 10}]
    assert len(h.get()) == 1
    h.set([{"network": "1.0.0.0", "mask": "255.0.0.0", "metric": 5}])
    assert len(h.get()) == 1


def test_routes_holder_in_form(app):
    app._on_attack_select("route-inject")
    assert "external_routes" in app._form._widgets


# -- roundtrip --

def test_config_roundtrip(app, tmp_path):
    import yaml
    app._on_attack_select("route-inject")
    d1 = app._form.get_config_dict()
    path = tmp_path / "cfg.yaml"
    d1["attack"] = "route-inject"
    with open(path, "w") as f:
        yaml.dump(d1, f)
    with open(path) as f:
        data = yaml.safe_load(f)
    data.pop("attack", None)
    app._form.set_config_dict(data)
    d2 = app._form.get_config_dict()
    for k in ("metric", "network_addr", "network_mask"):
        if k in d1:
            assert str(d2.get(k, "")) == str(d1[k]), f"{k}: {d1[k]} vs {d2.get(k)}"


# -- CLI --

def test_13_in_registry():
    from isis_attack.cli.commands import ATTACK_REGISTRY
    assert len(ATTACK_REGISTRY) == 13


def test_13_have_specific_fields():
    from isis_attack.gui.config_form import SPECIFIC_FIELDS
    names = [
        "iih-inject","adjacency-break","dis-hijack",
        "route-inject","max-seq","purge-lsp","fight-back","overload-bit",
        "flood","spf-recalc","db-overflow","mitm","replay"]
    for n in names:
        assert n in SPECIFIC_FIELDS, f"Missing SPECIFIC_FIELDS for {n}"
