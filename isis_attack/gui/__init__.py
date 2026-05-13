"""ISIS 攻击模拟器 GUI — python -m isis_attack 启动操作面板。"""

def launch_gui():
    from isis_attack.gui.app import MainWindow
    app = MainWindow()
    app.run()
