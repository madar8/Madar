"""Madar — isolated HR operations service. Python 3.12+, standard library only."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlparse
import argparse, base64, datetime as dt, getpass, hashlib, hmac, json, os, re, secrets, sqlite3, time

ROOT = Path(__file__).parent
DATA = Path(os.environ.get('MADAR_DATA_DIR', ROOT / 'data'))
SECURE = os.environ.get('MADAR_SECURE_COOKIE') == '1'
SESSION_SECONDS = 8 * 3600
MODULES = {
 'companies': ['name','sector','contact','email','plan','status'],
 'employees': ['name','email','phone','title','department','start_date','status','base','allowance','deduction','leave_balance'],
 'jobs': ['title','department','location','openings','status','description'],
 'candidates': ['name','email','phone','job_id','stage','notes'],
 'requests': ['employee_id','kind','start_date','end_date','reason','status'],
 'attendance': ['employee_id','day','check_in','check_out'],
 'contracts': ['employee_id','title','start_date','end_date','status','notes'],
 'tickets': ['title','priority','description','status'],
 'invoices': ['title','amount','tax_bps','due_date','status'],
 'documents': ['title','employee_id','expires','filename','mime','storage'],
 'payroll': ['period','status','items','total'],
}
STATES = {'employees': {'نشط','غير نشط'}, 'companies': {'نشط','موقوف'}, 'jobs': {'مفتوحة','مغلقة'},
 'candidates': {'جديد','فرز','مقابلة','عرض','تم التوظيف','مرفوض'}, 'requests': {'معلق','موافق','مرفوض'},
 'tickets': {'جديد','قيد المعالجة','مغلق'}, 'contracts': {'مسودة','ساري','منتهي'}, 'invoices': {'مسودة','مرسلة','مدفوعة'}}
READ = {
 'owner': set(MODULES), 'hr': set(MODULES),
 'client': set(MODULES)-{'companies'},
 'employee': {'employees','requests','attendance','documents','contracts','payroll','tickets'},
}
WRITE = {'owner': set(MODULES)-{'payroll','documents'}, 'hr': set(MODULES)-{'payroll','documents'},
 'client': {'jobs','tickets','requests'}, 'employee': {'requests','attendance','tickets'}}
class Problem(Exception):
 def __init__(self, message, code=400): self.message, self.code = message, code

def now(): return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
def today(): return (dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=3)).date().isoformat()
def connect():
 DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
 c=sqlite3.connect(DATA/'madar.db', timeout=15)
 c.row_factory=sqlite3.Row
 c.execute('PRAGMA foreign_keys=ON')
 return c

def migrate():
 with connect() as c:
  c.execute('PRAGMA journal_mode=WAL')
  c.executescript('''
  CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT NOT NULL UNIQUE COLLATE NOCASE,name TEXT NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('owner','hr','client','employee')),company_id TEXT,employee_id TEXT,active INTEGER NOT NULL DEFAULT 1);
  CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,csrf TEXT NOT NULL,expires REAL NOT NULL);
  CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY,module TEXT NOT NULL,company_id TEXT,data TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1,created TEXT NOT NULL,updated TEXT NOT NULL);
  CREATE INDEX IF NOT EXISTS records_scope ON records(module,company_id);
  CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT,actor TEXT NOT NULL,action TEXT NOT NULL,module TEXT NOT NULL,record_id TEXT,company_id TEXT,created TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS login_attempts(key TEXT PRIMARY KEY,attempts INTEGER NOT NULL,reset REAL NOT NULL);
  CREATE UNIQUE INDEX IF NOT EXISTS payroll_unique ON records(company_id,json_extract(data,'$.period')) WHERE module='payroll';
  CREATE UNIQUE INDEX IF NOT EXISTS attendance_unique ON records(company_id,json_extract(data,'$.employee_id'),json_extract(data,'$.day')) WHERE module='attendance';
  ''')

def hash_password(password):
 if not isinstance(password,str) or len(password)<12 or len(password)>200: raise Problem('كلمة المرور من 12 إلى 200 حرف')
 salt=secrets.token_hex(16)
 return salt+':'+hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1).hex()
def verify(password, stored):
 try:
  salt,digest=stored.split(':')
  return hmac.compare_digest(hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1).hex(),digest)
 except (ValueError,AttributeError): return False

def unpack(row):
 return {'id':row['id'],'company_id':row['company_id'],'version':row['version'],'created':row['created'],'updated':row['updated'],**json.loads(row['data'])}
def log(c,u,action,module,rid=None,cid=None):
 c.execute('INSERT INTO audit(user_id,actor,action,module,record_id,company_id,created) VALUES(?,?,?,?,?,?,?)',(u['id'],u['name'],action,module,rid,cid,now()))
def record(c,module,rid):
 r=c.execute('SELECT * FROM records WHERE module=? AND id=?',(module,rid)).fetchone()
 if not r: raise Problem('السجل غير موجود',404)
 return unpack(r)
def scoped(u,r,module):
 if u['role'] in ('owner','hr'): return True
 if r.get('company_id')!=u['company_id']: return False
 if u['role']=='employee':
  if module=='employees': return r['id']==u['employee_id']
  if module in ('contracts','requests','attendance','documents'): return r.get('employee_id')==u['employee_id']
  if module=='tickets': return r.get('created_by')==u['id']
 return True

def collection(c,u,module):
 if module not in READ[u['role']]: raise Problem('ليست لديك صلاحية',403)
 rows=c.execute('SELECT * FROM records WHERE module=? ORDER BY created DESC',(module,)).fetchall() if u['role'] in ('owner','hr') else c.execute('SELECT * FROM records WHERE module=? AND company_id=? ORDER BY created DESC',(module,u['company_id'])).fetchall()
 out=[]
 for row in rows:
  r=unpack(row)
  if not scoped(u,r,module): continue
  if module=='payroll' and u['role']=='employee':
   if r['status']!='معتمد': continue
   r['items']=[x for x in r['items'] if x['employee_id']==u['employee_id']]
   if not r['items']: continue
   r['total']=sum(x['net'] for x in r['items'])
  out.append(r)
 return out

def required(d,k):
 if not isinstance(d.get(k),str) or not d[k].strip(): raise Problem('حقل مطلوب: '+k)
def date(d,k,optional=True):
 if not d.get(k):
  if optional: return
  raise Problem('التاريخ مطلوب: '+k)
 try: dt.date.fromisoformat(d[k])
 except (ValueError,TypeError): raise Problem('تاريخ غير صالح: '+k)
def number(d,k,default=0):
 v=d.get(k,default)
 if isinstance(v,bool) or not isinstance(v,int) or v<0 or v>100_000_000: raise Problem('القيمة يجب أن تكون عددًا صحيحًا غير سالب: '+k)
 d[k]=v

def validate(c,u,module,body,old=None):
 if not isinstance(body,dict): raise Problem('بيانات غير صالحة')
 allowed=set(MODULES[module])|{'company_id','version'}
 if set(body)-allowed: raise Problem('حقول غير مدعومة')
 d={k:v for k,v in body.items() if k in MODULES[module]}
 for k,v in d.items():
  if k not in ('base','allowance','deduction','leave_balance','openings','amount','tax_bps') and not isinstance(v,str): raise Problem('نوع بيانات غير صالح: '+k)
 if any(isinstance(v,str) and len(v)>12000 for v in d.values()): raise Problem('النص طويل جدًا')
 cid=old.get('company_id') if old else body.get('company_id')
 if module=='companies': cid=None
 else:
  cid=cid if u['role'] in ('owner','hr') else u['company_id']
  if not cid: raise Problem('اختر الشركة')
  company=record(c,'companies',cid)
  if company['status']=='موقوف' and not old: raise Problem('الشركة موقوفة')
 if old and u['role']=='employee': raise Problem('لا يسمح بتعديل السجل بعد إرساله',403)
 if module in STATES:
  key='stage' if module=='candidates' else 'status'
  d.setdefault(key,old[key] if old else ('جديد' if module in ('candidates','tickets') else 'معلق' if module=='requests' else 'نشط' if module in ('employees','companies') else 'مفتوحة' if module=='jobs' else 'مسودة'))
  if d[key] not in STATES[module]: raise Problem('حالة غير صالحة')
 if module in ('companies','employees','candidates'): required(d,'name')
 if module in ('jobs','contracts','tickets','invoices'): required(d,'title')
 if module=='companies': required(d,'contact')
 if module=='employees':
  required(d,'title'); date(d,'start_date',False)
  for k in ('base','allowance','deduction','leave_balance'): number(d,k,21 if k=='leave_balance' else 0)
 if module=='jobs': number(d,'openings',1)
 if module=='candidates':
  job=record(c,'jobs',d.get('job_id'))
  if job['company_id']!=cid: raise Problem('الوظيفة خارج الشركة',403)
 if module in ('contracts','requests','attendance','documents'):
  eid=u['employee_id'] if u['role']=='employee' else d.get('employee_id')
  if not eid: raise Problem('اختر الموظف')
  employee=record(c,'employees',eid)
  if employee['company_id']!=cid: raise Problem('الموظف خارج الشركة',403)
  d['employee_id']=eid
 if module in ('requests','contracts'):
  date(d,'start_date',False);date(d,'end_date',False)
  if d['end_date']<d['start_date']: raise Problem('تاريخ النهاية يسبق البداية')
 if module=='requests':
  if d.get('kind') not in ('إجازة','خطاب تعريف','طلب عام'): raise Problem('نوع الطلب غير صالح')
  if old and d['status']!=old['status']: raise Problem('استخدم إجراء الموافقة أو الرفض')
  if not old: d['status']='معلق'
 if module=='attendance':
  # Attendance is server timestamped, preventing fabricated arrival times.
  if old: raise Problem('استخدم إجراء الانصراف')
  if any(d.get(k) for k in ('check_in','check_out','day')): raise Problem('وقت الحضور يسجل تلقائيًا')
  d.update(day=today(),check_in=now(),check_out='')
 if module=='invoices':
  number(d,'amount');number(d,'tax_bps');date(d,'due_date',False)
  if d['tax_bps']>10000: raise Problem('نسبة الضريبة غير صالحة')
 if module=='tickets':
  if d.get('priority') not in ('عادي','عاجل'): raise Problem('الأولوية غير صالحة')
 if old and 'created_by' in old: d['created_by']=old['created_by']
 else: d['created_by']=u['id']
 return cid,d

def insert(c,module,cid,d):
 rid=secrets.token_hex(12);stamp=now()
 c.execute('INSERT INTO records(id,module,company_id,data,created,updated) VALUES(?,?,?,?,?,?)',(rid,module,cid,json.dumps(d,ensure_ascii=False),stamp,stamp))
 return record(c,module,rid)
def replace(c,module,r,d,version):
 if version!=r['version']: raise Problem('السجل تغير؛ حدّث الصفحة ثم أعد المحاولة',409)
 changed=c.execute('UPDATE records SET data=?,version=version+1,updated=? WHERE id=? AND version=?',(json.dumps(d,ensure_ascii=False),now(),r['id'],version)).rowcount
 if not changed: raise Problem('تعارض تحديث',409)
 return record(c,module,r['id'])

def create_record(c,u,module,body,rid=None):
 if module not in WRITE[u['role']]: raise Problem('ليست لديك صلاحية للتعديل',403)
 old=record(c,module,rid) if rid else None
 if old and not scoped(u,old,module): raise Problem('ليست لديك صلاحية',403)
 if old and module=='requests': raise Problem('الطلبات لا تعدل بعد الإرسال؛ استخدم الموافقة أو الرفض')
 cid,d=validate(c,u,module,body,old)
 if u['role']=='client' and module=='requests' and old: raise Problem('استخدم إجراء الموافقة أو الرفض')
 result=replace(c,module,old,d,body.get('version')) if old else insert(c,module,cid,d)
 log(c,u,'تعديل' if old else 'إنشاء',module,result['id'],cid)
 return result

def payroll_create(c,u,body):
 if u['role'] not in ('owner','hr'): raise Problem('ليست لديك صلاحية',403)
 cid=body.get('company_id');record(c,'companies',cid)
 period=body.get('period','')
 try:
  if dt.date.fromisoformat(period+'-01').strftime('%Y-%m')!=period: raise ValueError()
 except (TypeError,ValueError): raise Problem('الفترة بصيغة YYYY-MM')
 employees=[x for x in collection(c,u,'employees') if x['company_id']==cid and x['status']=='نشط']
 if not employees: raise Problem('لا يوجد موظفون نشطون')
 items=[]
 for e in employees:
  gross=e['base']+e['allowance'];net=gross-e['deduction']
  if net<0: raise Problem('الخصومات تتجاوز المستحقات: '+e['name'])
  items.append({'employee_id':e['id'],'name':e['name'],'base':e['base'],'allowance':e['allowance'],'deduction':e['deduction'],'net':net})
 result=insert(c,'payroll',cid,{'period':period,'status':'مسودة','items':items,'total':sum(x['net'] for x in items),'created_by':u['id']})
 log(c,u,'إنشاء مسودة رواتب','payroll',result['id'],cid)
 return result

def action(c,u,module,rid,body):
 r=record(c,module,rid)
 if module not in READ[u['role']] or not scoped(u,r,module): raise Problem('ليست لديك صلاحية',403)
 d={k:v for k,v in r.items() if k not in ('id','company_id','version','created','updated')}
 act=body.get('action')
 if module=='requests' and act in ('approve','reject'):
  if u['role'] not in ('owner','hr','client'): raise Problem('ليست لديك صلاحية',403)
  if r['status']!='معلق': raise Problem('تم البت في الطلب',409)
  if u['employee_id']==r['employee_id']: raise Problem('لا يمكن اعتماد طلبك الشخصي',403)
  if act=='approve' and r['kind']=='إجازة':
   days=(dt.date.fromisoformat(r['end_date'])-dt.date.fromisoformat(r['start_date'])).days+1
   emp=record(c,'employees',r['employee_id'])
   if emp['leave_balance']<days: raise Problem('رصيد الإجازات غير كافٍ')
   overlaps=c.execute("SELECT data FROM records WHERE module='requests' AND json_extract(data,'$.employee_id')=? AND json_extract(data,'$.status')='موافق' AND json_extract(data,'$.kind')='إجازة'",(r['employee_id'],)).fetchall()
   if any(json.loads(x['data'])['start_date']<=r['end_date'] and json.loads(x['data'])['end_date']>=r['start_date'] for x in overlaps): raise Problem('توجد إجازة معتمدة في الفترة نفسها')
   ed={k:v for k,v in emp.items() if k not in ('id','company_id','version','created','updated')};ed['leave_balance']-=days
   replace(c,'employees',emp,ed,emp['version'])
  d.update(status='موافق' if act=='approve' else 'مرفوض',reviewed_by=u['id'],reviewed_at=now())
 elif module=='attendance' and act=='checkout':
  if u['role']=='client': raise Problem('ليست لديك صلاحية',403)
  if r['check_out']: raise Problem('تم تسجيل الانصراف',409)
  d['check_out']=now()
 elif module=='payroll' and act=='approve':
  if u['role'] not in ('owner','client'): raise Problem('الاعتماد للمالك أو مسؤول العميل',403)
  if r['status']!='مسودة': raise Problem('المسير معتمد بالفعل',409)
  if r.get('created_by')==u['id']: raise Problem('يجب أن يعتمد المسير مستخدم آخر للفصل بين الإعداد والاعتماد',403)
  d.update(status='معتمد',approved_by=u['id'],approved_at=now())
 else: raise Problem('إجراء غير مدعوم')
 result=replace(c,module,r,d,body.get('version'))
 log(c,u,act,module,rid,r['company_id']);return result

class Handler(BaseHTTPRequestHandler):
 server_version='Madar'
 def log_message(self,fmt,*args): pass # Never log cookies, credentials or record payloads.
 def reply(self,status,payload,cookie=None):
  content=json.dumps(payload,ensure_ascii=False).encode()
  self.send_response(status);self.headers_out('application/json; charset=utf-8',len(content))
  if cookie: self.send_header('Set-Cookie',cookie)
  self.end_headers();self.wfile.write(content)
 def headers_out(self,mime,size):
  self.send_header('Content-Type',mime);self.send_header('Content-Length',str(size));self.send_header('Cache-Control','no-store')
  self.send_header('X-Content-Type-Options','nosniff');self.send_header('X-Frame-Options','DENY');self.send_header('Referrer-Policy','same-origin')
  self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
 def body(self):
  try: length=int(self.headers.get('Content-Length','0'))
  except ValueError: raise Problem('حجم غير صالح')
  if length<0 or length>7_100_000: raise Problem('الحد الأقصى 5 ميغابايت للملف',413)
  try: result=json.loads(self.rfile.read(length))
  except (ValueError,UnicodeError): raise Problem('صيغة JSON غير صالحة')
  if not isinstance(result,dict): raise Problem('البيانات يجب أن تكون كائن JSON')
  return result
 def session(self,c):
  cookie=SimpleCookie()
  try: cookie.load(self.headers.get('Cookie',''));raw=cookie['madar_session'].value
  except (KeyError,ValueError): raise Problem('سجل الدخول أولًا',401)
  token=hashlib.sha256(raw.encode()).hexdigest()
  row=c.execute('SELECT users.*,sessions.csrf FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token=? AND sessions.expires>? AND users.active=1',(token,time.time())).fetchone()
  if not row: raise Problem('انتهت الجلسة؛ سجل الدخول',401)
  return dict(row),token
 def csrf(self,u):
  if not hmac.compare_digest(self.headers.get('X-CSRF-Token',''),u['csrf']): raise Problem('رمز الحماية غير صالح؛ حدّث الصفحة',403)
 def cookie(self,token,clear=False): return 'madar_session='+token+'; HttpOnly; SameSite=Strict; Path=/; Max-Age='+('0' if clear else str(SESSION_SECONDS))+('; Secure' if SECURE else '')
 def dispatch(self):
  path=urlparse(self.path).path
  if self.command=='POST' and self.headers.get('Origin'):
   if urlparse(self.headers['Origin']).netloc != self.headers.get('Host'): raise Problem('مصدر الطلب غير مسموح',403)
  if not path.startswith('/api/'):
   if self.command!='GET': raise Problem('غير مسموح',405)
   name={'/':'index.html','/app':'index.html','/styles.css':'styles.css','/app.js':'app.js'}.get(path)
   if not name: raise Problem('الصفحة غير موجودة',404)
   data=(ROOT/'web'/name).read_bytes();self.send_response(200);self.headers_out('text/html; charset=utf-8' if name.endswith('.html') else 'text/css; charset=utf-8' if name.endswith('.css') else 'text/javascript; charset=utf-8',len(data));self.end_headers();self.wfile.write(data);return
  if path=='/api/health' and self.command=='GET': return self.reply(200,{'status':'ok','version':'0.1.0'})
  with connect() as c:
   if self.command=='POST': c.execute('BEGIN IMMEDIATE')
   if path=='/api/login' and self.command=='POST':
    body=self.body();email=str(body.get('email','')).strip().lower();password=body.get('password','')
    if not isinstance(password,str) or len(password)>200: raise Problem('بيانات الدخول غير صحيحة',401)
    key=hashlib.sha256(email.encode()).hexdigest();attempt=c.execute('SELECT * FROM login_attempts WHERE key=?',(key,)).fetchone()
    if attempt and attempt['reset']>time.time() and attempt['attempts']>=10: raise Problem('محاولات كثيرة؛ أعد المحاولة بعد 15 دقيقة',429)
    user=c.execute('SELECT * FROM users WHERE email=? AND active=1',(email,)).fetchone()
    if not user or not verify(password,user['password']):
     count=attempt['attempts']+1 if attempt and attempt['reset']>time.time() else 1
     reset=attempt['reset'] if attempt and attempt['reset']>time.time() else time.time()+900
     c.execute('INSERT OR REPLACE INTO login_attempts VALUES(?,?,?)',(key,count,reset));c.commit();raise Problem('البريد أو كلمة المرور غير صحيحة',401)
    c.execute('DELETE FROM login_attempts WHERE key=?',(key,));c.execute('DELETE FROM sessions WHERE expires<?',(time.time(),))
    raw=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
    c.execute('INSERT INTO sessions VALUES(?,?,?,?)',(hashlib.sha256(raw.encode()).hexdigest(),user['id'],csrf,time.time()+SESSION_SECONDS));log(c,dict(user),'تسجيل دخول','users');c.commit()
    return self.reply(200,{'ok':True},self.cookie(raw))
   u,token=self.session(c)
   if self.command=='POST': self.csrf(u)
   if path=='/api/me' and self.command=='GET': return self.reply(200,{k:u[k] for k in ('id','name','email','role','company_id','employee_id','csrf')})
   if path=='/api/logout' and self.command=='POST':
    c.execute('DELETE FROM sessions WHERE token=?',(token,));c.commit();return self.reply(200,{'ok':True},self.cookie('',True))
   if path=='/api/users':
    if u['role']!='owner': raise Problem('للمالك فقط',403)
    if self.command=='GET': return self.reply(200,[dict(r) for r in c.execute('SELECT id,name,email,role,company_id,employee_id,active FROM users')])
    if self.command=='POST':
     b=self.body();required(b,'name');required(b,'email')
     if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',b['email']): raise Problem('بريد غير صالح')
     if b.get('role') not in READ: raise Problem('دور غير صالح')
     cid=b.get('company_id') or None;eid=b.get('employee_id') or None
     if b['role'] in ('client','employee'):
      record(c,'companies',cid)
      if b['role']=='employee' and record(c,'employees',eid)['company_id']!=cid: raise Problem('الموظف خارج الشركة')
     else: cid=eid=None
     uid=secrets.token_hex(12)
     c.execute('INSERT INTO users(id,name,email,password,role,company_id,employee_id) VALUES(?,?,?,?,?,?,?)',(uid,b['name'],b['email'].strip().lower(),hash_password(b.get('password')),b['role'],cid,eid));log(c,u,'إنشاء مستخدم','users',uid,cid);c.commit();return self.reply(201,{'id':uid})
   if path.startswith('/api/users/') and self.command=='POST':
    if u['role']!='owner': raise Problem('للمالك فقط',403)
    uid=path.split('/')[-1];b=self.body()
    target=c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
    if not target: raise Problem('المستخدم غير موجود',404)
    if uid==u['id']: raise Problem('لا يمكنك تعطيل حسابك أو تغييره من هنا')
    if b.get('action')=='disable': c.execute('UPDATE users SET active=0 WHERE id=?',(uid,))
    elif b.get('action')=='reset': c.execute('UPDATE users SET password=? WHERE id=?',(hash_password(b.get('password')),uid))
    else: raise Problem('إجراء غير صالح')
    c.execute('DELETE FROM sessions WHERE user_id=?',(uid,));log(c,u,b['action'],'users',uid,target['company_id']);c.commit();return self.reply(200,{'ok':True})
   if path=='/api/audit' and self.command=='GET':
    if u['role'] not in ('owner','hr'): raise Problem('ليست لديك صلاحية',403)
    return self.reply(200,[dict(r) for r in c.execute('SELECT actor,action,module,record_id,company_id,created FROM audit ORDER BY id DESC LIMIT 500')])
   if path=='/api/password' and self.command=='POST':
    b=self.body()
    if not verify(b.get('current',''),u['password']): raise Problem('كلمة المرور الحالية غير صحيحة',403)
    c.execute('UPDATE users SET password=? WHERE id=?',(hash_password(b.get('password')),u['id']));c.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],));log(c,u,'تغيير كلمة المرور','users',u['id']);c.commit();return self.reply(200,{'ok':True},self.cookie('',True))
   if path=='/api/backup' and self.command=='GET':
    if u['role']!='owner': raise Problem('للمالك فقط',403)
    return self.reply(200,{'exported_at':now(),'records':{m:collection(c,u,m) for m in MODULES},'note':'تصدير بيانات فقط، النسخ الكامل يشمل قاعدة البيانات وملفات المستندات بأداة backup.py'})
   parts=path.strip('/').split('/');module=parts[1] if len(parts)>1 else ''
   if module not in MODULES: raise Problem('المسار غير موجود',404)
   if len(parts)==2:
    if self.command=='GET': return self.reply(200,collection(c,u,module))
    if self.command=='POST':
     b=self.body()
     if module=='payroll': result=payroll_create(c,u,b)
     elif module=='documents': result=self.upload(c,u,b)
     else: result=create_record(c,u,module,b)
     c.commit();return self.reply(201,result)
   if len(parts)==4 and parts[3]=='download' and module=='documents' and self.command=='GET':
    r=record(c,module,parts[2])
    if not scoped(u,r,module) or module not in READ[u['role']]: raise Problem('ليست لديك صلاحية',403)
    data=(DATA/'files'/r['storage']).read_bytes()
    self.send_response(200);self.headers_out(r['mime'],len(data));self.send_header('Content-Disposition','attachment; filename="document.'+r['storage'].split('.')[-1]+'"');self.end_headers();self.wfile.write(data);return
   if len(parts)==3 and self.command=='POST': result=create_record(c,u,module,self.body(),parts[2])
   elif len(parts)==4 and parts[3]=='action' and self.command=='POST': result=action(c,u,module,parts[2],self.body())
   else: raise Problem('المسار غير موجود',404)
   c.commit();self.reply(200,result)
 def upload(self,c,u,b):
  if u['role'] not in ('owner','hr','client'): raise Problem('ليست لديك صلاحية',403)
  required(b,'title');required(b,'filename')
  cid=b.get('company_id') if u['role'] in ('owner','hr') else u['company_id'];record(c,'companies',cid)
  eid=b.get('employee_id')
  if not eid or record(c,'employees',eid)['company_id']!=cid: raise Problem('اختر موظفًا من الشركة')
  date(b,'expires')
  try: data=base64.b64decode(b.get('content',''),validate=True)
  except (ValueError,TypeError): raise Problem('ملف غير صالح')
  if not data or len(data)>5*1024*1024: raise Problem('الملف فارغ أو يتجاوز 5 ميغابايت',413)
  ext=Path(b['filename']).suffix.lower()
  magic={'.pdf':(b'%PDF-','application/pdf'),'.png':(b'\x89PNG\r\n\x1a\n','image/png'),'.jpg':(b'\xff\xd8\xff','image/jpeg'),'.jpeg':(b'\xff\xd8\xff','image/jpeg')}
  if ext not in magic or not data.startswith(magic[ext][0]): raise Problem('المسموح PDF أو PNG أو JPG مطابق لنوعه')
  storage=secrets.token_hex(24)+ext;directory=DATA/'files';directory.mkdir(exist_ok=True,mode=0o700)
  (directory/storage).write_bytes(data)
  result=insert(c,'documents',cid,{'title':b['title'],'filename':Path(b['filename']).name,'employee_id':eid,'expires':b.get('expires',''),'mime':magic[ext][1],'storage':storage,'created_by':u['id']})
  log(c,u,'رفع مستند','documents',result['id'],cid);return result
 def do_GET(self): self.handle_request()
 def do_POST(self): self.handle_request()
 def handle_request(self):
  try: self.dispatch()
  except Problem as e: self.reply(e.code,{'error':e.message})
  except sqlite3.IntegrityError: self.reply(409,{'error':'سجل مكرر: تحقق من البريد أو فترة الرواتب أو حضور اليوم'})
  except (BrokenPipeError,ConnectionResetError): pass
  except Exception as e:
   print('Request failed:',type(e).__name__,flush=True);self.reply(500,{'error':'تعذر تنفيذ العملية؛ راجع مسؤول النظام'})

def setup(email,name,password):
 with connect() as c:
  if c.execute('SELECT count(*) FROM users').fetchone()[0]: raise Problem('تم إنشاء حساب المالك مسبقًا')
  uid=secrets.token_hex(12);c.execute('INSERT INTO users(id,email,name,password,role) VALUES(?,?,?,?,?)',(uid,email.strip().lower(),name,hash_password(password),'owner'))
 return uid

def demo():
 if not os.environ.get('MADAR_DATA_DIR'): raise Problem('حدد MADAR_DATA_DIR منفصلًا للبيانات التجريبية')
 password=secrets.token_urlsafe(15);uid=setup('owner@madar.test','مدير مدار',password)
 with connect() as c:
  u=dict(c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone())
  for name,sector,contact in [('أفق للتقنية','التقنية','سارة العتيبي'),('نواة للتجارة','التجارة','خالد الدوسري'),('مدى للاستشارات','الاستشارات','نورة الحربي')]:
   co=create_record(c,u,'companies',dict(name=name,sector=sector,contact=contact,email='hello@example.test',plan='إدارة متكاملة',status='نشط'))
   for person,title,dept,base in [('ريم القحطاني','أخصائية موارد بشرية','الموارد البشرية',850000),('محمد العتيبي','مدير مشاريع','العمليات',1200000),('سارة الغامدي','محللة أعمال','التقنية',950000)]:
    e=create_record(c,u,'employees',dict(company_id=co['id'],name=person,title=title,department=dept,start_date='2026-01-01',base=base,allowance=150000,deduction=0,leave_balance=21,status='نشط',email='person@example.test',phone=''))
    create_record(c,u,'requests',dict(company_id=co['id'],employee_id=e['id'],kind='إجازة',start_date='2026-12-01',end_date='2026-12-03',reason='إجازة سنوية'))
   job=create_record(c,u,'jobs',dict(company_id=co['id'],title='أخصائي نجاح عملاء',department='العمليات',location='الرياض',openings=2,status='مفتوحة',description='إدارة العلاقة مع العملاء وتحسين تجربة الخدمة'))
   create_record(c,u,'candidates',dict(company_id=co['id'],name='عبدالله السبيعي',email='candidate@example.test',phone='',job_id=job['id'],stage='مقابلة',notes=''))
   create_record(c,u,'tickets',dict(company_id=co['id'],title='تجهيز خطة التهيئة للموظفين الجدد',priority='عادي',description='مراجعة متطلبات أول أسبوع',status='قيد المعالجة'))
 print('بيانات تجريبية فقط. البريد: owner@madar.test  كلمة المرور:',password)

if __name__=='__main__':
 parser=argparse.ArgumentParser(description='Madar HR operations')
 parser.add_argument('command',nargs='?',choices=['serve','init','demo'],default='serve');parser.add_argument('--email');parser.add_argument('--name',default='مدير مدار');parser.add_argument('--host',default='127.0.0.1');parser.add_argument('--port',type=int,default=8000)
 args=parser.parse_args();migrate()
 try:
  if args.command=='init':
   email=args.email or input('بريد المالك: ');password=getpass.getpass('كلمة مرور (12 حرفًا على الأقل): ')
   if getpass.getpass('تأكيد كلمة المرور: ')!=password: raise Problem('كلمتا المرور غير متطابقتين')
   setup(email,args.name,password);print('تم إنشاء المالك. شغّل: python server.py')
  elif args.command=='demo': demo()
  else:
   print(f'Madar listening on http://{args.host}:{args.port}',flush=True)
   ThreadingHTTPServer((args.host,args.port),Handler).serve_forever()
 except Problem as e: parser.exit(1,e.message+'\n')
