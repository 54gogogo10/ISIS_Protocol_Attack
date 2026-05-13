"""ISIS attack simulator GUI entry point — python -m isis_attack launches the control panel."""
import warnings
warnings.filterwarnings("ignore", message=".*No route found.*")

from isis_attack.gui import launch_gui

if __name__ == "__main__":
    launch_gui()
