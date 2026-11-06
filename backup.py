"""Consistent SQLite backup plus attachments. Run with the application stopped."""
from pathlib import Path
import argparse, datetime, os, sqlite3, tempfile, zipfile

def backup(source, destination):
 source=Path(source).resolve();destination=Path(destination).resolve()
 if not (source/'madar.db').is_file():raise ValueError('Database not found')
 if destination.exists():raise ValueError('Destination exists; choose a new filename')
 destination.parent.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory() as td:
  copied=Path(td)/'madar.db'
  with sqlite3.connect(source/'madar.db') as src,sqlite3.connect(copied) as dst:
   src.backup(dst)
   if dst.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('Backup integrity check failed')
  fd=os.open(destination,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
  with os.fdopen(fd,'wb') as out,zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
   z.write(copied,'madar.db')
   for file in (source/'files').glob('*'):
    if file.is_file():z.write(file,'files/'+file.name)
 return destination
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--data',default=os.environ.get('MADAR_DATA_DIR','data'));p.add_argument('--output',required=True);a=p.parse_args()
 print(backup(a.data,a.output))
