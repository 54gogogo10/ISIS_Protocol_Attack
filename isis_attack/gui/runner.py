"""后台攻击线程运行器。"""
import threading
from isis_attack.cli.commands import ATTACK_REGISTRY
from isis_attack.config.config import build_config


def run_attack_in_thread(attack_name: str, kwargs: dict, log_callback=None):
    """在后台线程中运行指定攻击。

    Args:
        attack_name: 攻击名称（如 "iih-inject"）
        kwargs: 配置参数字典
        log_callback: 完成回调，接收 AttackResult

    Returns:
        threading.Thread 或 None
    """
    if attack_name not in ATTACK_REGISTRY:
        return None

    attack_cls, config_cls = ATTACK_REGISTRY[attack_name]
    stop_event = threading.Event()

    def _run():
        config = build_config(attack_name, kwargs)
        attack = attack_cls(config, stop_event=stop_event)
        result = attack.run()
        if log_callback:
            log_callback(result)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t
