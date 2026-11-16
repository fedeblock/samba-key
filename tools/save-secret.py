#!/usr/bin/env python3
"""Guardar secretos de Samba Key en archivos solo legibles por root."""
import getpass
import os
import re
import sys
from pathlib import Path

names = {'telegram': 'telegram-token', 'smtp': 'smtp-password',
         'brevo': 'brevo-smtp-password'}
if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in names:
    raise SystemExit('Usage: sudo python3 tools/save-secret.py {telegram|smtp|brevo}')

root = Path('/etc/samba-key')
directory = root / 'secrets'
for path in (root, directory):
    if path.is_symlink():
        raise SystemExit('Se rechazó una ruta de secretos con enlace simbólico.')
    path.mkdir(mode=0o700, exist_ok=True)
    if not path.is_dir() or path.stat().st_uid != 0:
        raise SystemExit('La carpeta de secretos debe pertenecer a root.')
    os.chmod(path, 0o700)

target = directory / names[sys.argv[1]]
if target.exists() or target.is_symlink():
    raise SystemExit('El archivo ya existe; no se ha sobrescrito.')
value = getpass.getpass('Pegá el secreto (no se mostrará): ').strip()
if not value or '\n' in value or '\r' in value or '\x00' in value:
    raise SystemExit('Secreto vacío o inválido; no se guardó.')
if sys.argv[1] == 'telegram' and not re.fullmatch(r'[0-9]+:[A-Za-z0-9_-]{20,}', value):
    raise SystemExit('El formato del token de Telegram no parece válido; no se guardó.')
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        output.write(value + '\n')
except Exception:
    target.unlink(missing_ok=True)
    raise
print('Secreto guardado con permisos privados:', target)
