import threading
from isis_attack.cli.commands import ATTACK_REGISTRY
from isis_attack.config.config import build_config

def run_attack_in_thread(attack_name, kwargs, log_callback=None):
    if attack_name not in ATTACK_REGISTRY:
        return
    attack_cls, config_cls = ATTACK_REGISTRY[attack_name]

    def _run():
        config = build_config(attack_name, kwargs)
        attack = attack_cls(config)
        result = attack.run()
        if log_callback:
            log_callback(result)
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t
