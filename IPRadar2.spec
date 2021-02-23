# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(['IPRadar2.py'],
             pathex=['dist'],
             binaries=[],
             datas=[],
             hiddenimports=['py._path.local','py._vendored_packages.iniconfig','pyshark.config'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='IPRadar2',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True )



