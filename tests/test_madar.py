import concurrent.futures, http.cookiejar, importlib.util, json, os, pathlib, tempfile, threading, unittest, urllib.request, urllib.error
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('madar',ROOT/'server.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class MadarTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();m.DATA=pathlib.Path(cls.tmp.name);m.migrate();m.setup('owner@example.test','المالك','OwnerPassword123!')
  cls.server=m.ThreadingHTTPServer(('127.0.0.1',0),m.Handler);cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start();cls.base='http://127.0.0.1:'+str(cls.server.server_port)
 @classmethod
 def tearDownClass(cls): cls.server.shutdown();cls.server.server_close();cls.tmp.cleanup()
 def client(self,email='owner@example.test',password='OwnerPassword123!'):
  op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.call(op,'login',{'email':email,'password':password});status,user=self.call(op,'me');return op,user
 def call(self,op,path,body=None,csrf=None,origin=None):
  headers={'Content-Type':'application/json'}
  if csrf is not None: headers['X-CSRF-Token']=csrf
  if origin: headers['Origin']=origin
  req=urllib.request.Request(self.base+'/api/'+path,data=None if body is None else json.dumps(body).encode(),headers=headers)
  try:
   with op.open(req) as res: return res.status,json.loads(res.read())
  except urllib.error.HTTPError as e:return e.code,json.loads(e.read())
 def setUp(self):
  self.op,self.user=self.client();self.csrf=self.user['csrf']
  suffix=os.urandom(5).hex();self.co=self.post('companies',{'name':'شركة '+suffix,'contact':'مسؤول','status':'نشط'})
  self.co2=self.post('companies',{'name':'شركة أخرى '+suffix,'contact':'مسؤول','status':'نشط'})
  self.emp=self.post('employees',{'company_id':self.co['id'],'name':'موظف','title':'محلل','start_date':'2026-01-01','base':1000000,'allowance':200000,'deduction':50000,'leave_balance':21})
  self.emp2=self.post('employees',{'company_id':self.co2['id'],'name':'آخر','title':'محلل','start_date':'2026-01-01','base':900000,'allowance':0,'deduction':0,'leave_balance':21})
 def post(self,path,body,status=201,op=None,user=None):
  code,r=self.call(op or self.op,path,body,(user or self.user)['csrf']);self.assertEqual(code,status,r);return r
 def make_user(self,role='client',company=None,employee=None):
  email=os.urandom(5).hex()+'@example.test';self.post('users',{'name':role,'email':email,'password':'ClientPassword123!','role':role,'company_id':company or self.co['id'],'employee_id':employee or self.emp['id']});return self.client(email,'ClientPassword123!')
 def request(self,**extra):return self.post('requests',{'company_id':self.co['id'],'employee_id':self.emp['id'],'kind':'إجازة','start_date':'2026-12-01','end_date':'2026-12-03','reason':'سنوية',**extra})
 def test_health_and_unauthorized(self):
  op=urllib.request.build_opener();self.assertEqual(self.call(op,'health')[0],200);self.assertEqual(self.call(op,'employees')[0],401)
 def test_password_hash_and_no_secret_leak(self):
  with m.connect() as c: self.assertNotIn('OwnerPassword',c.execute('SELECT password FROM users WHERE id=?',(self.user['id'],)).fetchone()[0])
  self.assertNotIn('password',self.user);self.assertNotIn('password',json.dumps(self.call(self.op,'users')[1]))
 def test_csrf_and_foreign_origin(self):
  self.assertEqual(self.call(self.op,'companies',{'name':'x','contact':'x'})[0],403)
  self.assertEqual(self.call(self.op,'companies',{'name':'x','contact':'x'},self.csrf,'https://evil.test')[0],403)
 def test_company_isolation_read_and_write(self):
  op,u=self.make_user();_,rows=self.call(op,'employees');self.assertEqual({r['id'] for r in rows},{self.emp['id']})
  self.post('jobs',{'company_id':self.co2['id'],'title':'وظيفة','openings':1},op=op,user=u)
  _,jobs=self.call(op,'jobs');self.assertTrue(all(x['company_id']==self.co['id'] for x in jobs))
 def test_client_cross_company_update_denied(self):
  op,u=self.make_user();job=self.post('jobs',{'company_id':self.co2['id'],'title':'خاصة','openings':1})
  self.post('jobs/'+job['id'],{'title':'تغيير','openings':1,'version':job['version']},403,op,u)
 def test_employee_sees_only_self(self):
  op,u=self.make_user('employee');self.assertEqual(len(self.call(op,'employees')[1]),1);self.assertEqual(self.call(op,'users')[0],403);self.assertEqual(self.call(op,'companies')[0],403)
 def test_employee_cannot_modify_salary(self):
  op,u=self.make_user('employee');self.post('employees/'+self.emp['id'],{'base':1,'version':1},403,op,u)
 def test_employee_request_identity_forced(self):
  op,u=self.make_user('employee');r=self.post('requests',{'employee_id':self.emp2['id'],'company_id':self.co2['id'],'kind':'طلب عام','start_date':'2026-12-01','end_date':'2026-12-02'},op=op,user=u);self.assertEqual(r['employee_id'],self.emp['id']);self.assertEqual(r['company_id'],self.co['id'])
 def test_leave_approval_once_and_balance(self):
  r=self.request();self.post('requests/'+r['id']+'/action',{'action':'approve','version':r['version']},200)
  self.post('requests/'+r['id']+'/action',{'action':'approve','version':r['version']},409)
  with m.connect() as c:self.assertEqual(m.record(c,'employees',self.emp['id'])['leave_balance'],18)
 def test_leave_insufficient_and_overlap(self):
  r=self.request(end_date='2027-01-01');self.post('requests/'+r['id']+'/action',{'action':'approve','version':1},400)
  r=self.request();self.post('requests/'+r['id']+'/action',{'action':'approve','version':1},200)
  r=self.request();self.post('requests/'+r['id']+'/action',{'action':'approve','version':1},400)
 def test_rejection_does_not_deduct(self):
  r=self.request();self.post('requests/'+r['id']+'/action',{'action':'reject','version':1},200)
  with m.connect() as c:self.assertEqual(m.record(c,'employees',self.emp['id'])['leave_balance'],21)
 def test_request_cannot_be_rewritten(self):
  r=self.request();self.post('requests/'+r['id'],{'employee_id':self.emp['id'],'kind':'إجازة','start_date':'2026-12-01','end_date':'2026-12-20','version':1},400)
 def test_stale_updates_rejected(self):
  body={'name':'تحديث','contact':'x','version':1};self.post('companies/'+self.co['id'],body,200);self.post('companies/'+self.co['id'],body,409)
 def test_payroll_precision_snapshot_duplicate(self):
  r=self.post('payroll',{'company_id':self.co['id'],'period':'2026-11'});self.assertEqual(r['total'],1150000)
  self.post('payroll',{'company_id':self.co['id'],'period':'2026-11'},409)
  e={k:v for k,v in self.emp.items() if k in m.MODULES['employees']};e.update(base=2000000,version=1);self.post('employees/'+self.emp['id'],e,200)
  with m.connect() as c:self.assertEqual(m.record(c,'payroll',r['id'])['total'],1150000)
 def test_payroll_separation_and_employee_payslip(self):
  r=self.post('payroll',{'company_id':self.co['id'],'period':'2026-10'});self.post('payroll/'+r['id']+'/action',{'action':'approve','version':1},403)
  employee,eu=self.make_user('employee');self.assertEqual(self.call(employee,'payroll')[1],[])
  op,u=self.make_user();self.post('payroll/'+r['id']+'/action',{'action':'approve','version':1},200,op,u)
  rows=self.call(employee,'payroll')[1];self.assertEqual(len(rows),1);self.assertEqual(len(rows[0]['items']),1)
 def test_attendance_timestamp_and_duplicate(self):
  r=self.post('attendance',{'company_id':self.co['id'],'employee_id':self.emp['id']});self.assertTrue(r['check_in']);self.post('attendance',{'company_id':self.co['id'],'employee_id':self.emp['id']},409)
  self.post('attendance/'+r['id']+'/action',{'action':'checkout','version':1},200);self.post('attendance/'+r['id']+'/action',{'action':'checkout','version':2},409)
 def test_unauthorized_document_download(self):
  import base64
  r=self.post('documents',{'company_id':self.co2['id'],'employee_id':self.emp2['id'],'title':'عقد','filename':'../../secret.pdf','content':base64.b64encode(b'%PDF-1.4\n test').decode()});op,u=self.make_user();self.assertEqual(self.call(op,'documents/'+r['id']+'/download')[0],403);self.assertEqual(r['filename'],'secret.pdf')
 def test_file_type_validation(self):
  import base64
  self.post('documents',{'company_id':self.co['id'],'employee_id':self.emp['id'],'title':'ملف','filename':'x.pdf','content':base64.b64encode(b'<script>alert(1)</script>').decode()},400)
 def test_disable_revokes_session(self):
  op,u=self.make_user();self.post('users/'+u['id'],{'action':'disable'},200);self.assertEqual(self.call(op,'me')[0],401)
 def test_logout_revokes(self):
  op,u=self.make_user();self.post('logout',{},200,op,u);self.assertEqual(self.call(op,'me')[0],401)
 def test_negative_money_and_dates(self):
  self.post('employees',{'company_id':self.co['id'],'name':'x','title':'x','base':-5,'start_date':'2026-01-01'},400)
  self.post('requests',{'company_id':self.co['id'],'employee_id':self.emp['id'],'kind':'إجازة','start_date':'2026-12-03','end_date':'2026-12-01'},400)
 def test_cross_company_reference(self):
  self.post('contracts',{'company_id':self.co['id'],'employee_id':self.emp2['id'],'title':'عقد','start_date':'2026-01-01','end_date':'2026-12-31'},403)
 def test_audit_no_sensitive_payloads(self):
  self.request();code,logs=self.call(self.op,'audit');self.assertEqual(code,200);self.assertTrue(logs);self.assertNotIn('password',json.dumps(logs));self.assertNotIn('reason',json.dumps(logs))
 def test_login_lockout(self):
  op=urllib.request.build_opener();email=os.urandom(5).hex()+'@example.test'
  for _ in range(10):self.assertEqual(self.call(op,'login',{'email':email,'password':'wrong'})[0],401)
  self.assertEqual(self.call(op,'login',{'email':email,'password':'wrong'})[0],429)
 def test_concurrent_approval_is_atomic(self):
  r=self.request();url='requests/'+r['id']+'/action'
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(lambda _:self.call(self.op,url,{'action':'approve','version':1},self.csrf)[0],range(2)))
  self.assertEqual(sorted(results),[200,409])
  with m.connect() as c:self.assertEqual(m.record(c,'employees',self.emp['id'])['leave_balance'],18)
 def test_backup_integrity(self):
  import zipfile, sqlite3
  spec=importlib.util.spec_from_file_location('backup',ROOT/'backup.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  with tempfile.TemporaryDirectory() as td:
   archive=pathlib.Path(td)/'backup.zip';module.backup(m.DATA,archive)
   with zipfile.ZipFile(archive) as z:
    self.assertIn('madar.db',z.namelist());z.extract('madar.db',td)
   with sqlite3.connect(pathlib.Path(td)/'madar.db') as c:self.assertEqual(c.execute('PRAGMA integrity_check').fetchone()[0],'ok')
if __name__=='__main__':unittest.main()
