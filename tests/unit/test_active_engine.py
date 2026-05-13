"""Basic tests for ActiveISISEngine — import and initialization."""
from isis_attack.core.active_engine import ActiveISISEngine, SniffedISISParams
from isis_attack.core.neighbor import ISNeighborState


class TestActiveISISEngineImport:
    def test_classes_importable(self):
        assert ActiveISISEngine is not None
        assert SniffedISISParams is not None

    def test_default_state_is_down(self):
        engine = ActiveISISEngine(iface="eth0", spoofed_sys_id="1921.6800.1001")
        assert engine.state == ISNeighborState.DOWN

    def test_init_attributes(self):
        engine = ActiveISISEngine(
            iface="eth1",
            spoofed_sys_id="AAAA.BBBB.CCCC",
            area_addr="49.0002",
            level=2,
        )
        assert engine.iface == "eth1"
        assert engine.spoofed_sys_id == "AAAA.BBBB.CCCC"
        assert engine.area_addr == "49.0002"
        assert engine.level == 2
        assert engine.hello_sent == 0
        assert engine.lsp_sent == 0
        assert engine.log == []

    def test_state_transitions(self):
        engine = ActiveISISEngine(iface="eth0", spoofed_sys_id="1921.6800.1001")
        assert engine.state == ISNeighborState.DOWN
        engine.state = ISNeighborState.INIT
        assert engine.state == ISNeighborState.INIT
        assert "[DOWN->INIT]" in engine.log
        engine.state = ISNeighborState.UP
        assert engine.state == ISNeighborState.UP
        assert "[INIT->UP]" in engine.log

    def test_shutdown_sets_stop_event(self):
        engine = ActiveISISEngine(iface="eth0", spoofed_sys_id="1921.6800.1001")
        assert engine._stop.is_set() is False
        engine.shutdown()
        assert engine._stop.is_set() is True

    def test_sniffed_params_defaults(self):
        params = SniffedISISParams()
        assert params.sys_id == ""
        assert params.area_addr == "49.0001"
        assert params.hello_interval == 10
        assert params.hold_timer == 30
        assert params.priority == 64
