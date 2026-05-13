"""ISIS attack simulator GUI."""
def launch_gui():
    import tkinter as tk
    from isis_attack.gui.app import ISISAttackApp
    root = tk.Tk()
    app = ISISAttackApp(root)
    root.mainloop()
