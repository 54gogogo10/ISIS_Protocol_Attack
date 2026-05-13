# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['isis_attack\\cli\\main.py'],
    pathex=[],
    binaries=[('assets/npcap-installer.exe', '.')],
    datas=[],
    hiddenimports=['scapy.contrib.isis', 'scapy.layers.l2', 'scapy.layers.inet', 'pcap', 'click', 'yaml'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='isis-attack',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
