import pytest
import threading
from isis_attack.attacks.base import BaseAttack
from isis_attack.config.types import AttackConfig, AttackResult, AttackMode, AttackCategory

class _DummyAttack(BaseAttack):
    name = "dummy"
    description = "test"
    category = AttackCategory.DOS
    def setup(self): pass
    def launch(self):
        return AttackResult(success=True, packets_sent=1, target_affected=False, details="dummy")
    def verify(self): return True
    def teardown(self): pass

def test_base_attack_run():
    config = AttackConfig(iface="eth0", target="01:80:C2:00:00:14")
    attack = _DummyAttack(config)
    result = attack.run()
    assert result.success
    assert result.packets_sent == 1

def test_base_attack_with_stop_event():
    config = AttackConfig(iface="eth0", target="01:80:C2:00:00:14")
    stop = threading.Event()
    attack = _DummyAttack(config, stop_event=stop)
    assert attack._stop_event is stop
