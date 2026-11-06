import importlib.util, io, json, os, pathlib, tempfile, unittest
from unittest.mock import patch
import sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import server, wsgi
class HostingTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.old=server.DATA;server.DATA=pathlib.Path(self.tmp.name);server.migrate()
  self.env=patch.dict(os.environ,{'MADAR_SETUP_TOKEN':'a'*48});self.env.start()
 def tearDown(self):self.env.stop();server.DATA=self.old;self.tmp.cleanup()
 def request(self,path,body=None,headers=None,method=None):
  raw=b'' if body is None else json.dumps(body).encode();environ={'REQUEST_METHOD':method or ('GET' if body is None else 'POST'),'PATH_INFO':path,'wsgi.input':io.BytesIO(raw),'CONTENT_LENGTH':str(len(raw)),'CONTENT_TYPE':'application/json','HTTP_HOST':'madar.example.test'};environ.update(headers or {})
  status=[];out_headers=[]
  def start(s,h):status.append(int(s.split()[0]));out_headers.extend(h)
  data=b''.join(wsgi.application(environ,start));return status[0],out_headers,data
 def bootstrap(self,**extra):return self.request('/api/setup',{'token':'a'*48,'email':'owner@madar.test','name':'مدير مدار','password':'StrongPassword123!',**extra})
 def test_setup_hidden_without_configuration(self):
  with patch.dict(os.environ,{'MADAR_SETUP_TOKEN':''}):self.assertEqual(self.bootstrap()[0],404)
 def test_first_setup_and_lock(self):
  self.assertTrue(json.loads(self.request('/api/health')[2])['setup_required']);self.assertEqual(self.bootstrap()[0],201);self.assertEqual(self.bootstrap()[0],409);self.assertFalse(json.loads(self.request('/api/health')[2])['setup_required'])
 def test_invalid_token_and_password(self):
  self.assertEqual(self.bootstrap(token='wrong')[0],403);self.assertEqual(self.bootstrap(password='short')[0],400);self.assertEqual(self.bootstrap(email='invalid')[0],400)
 def test_setup_rate_limit(self):
  for _ in range(10):self.assertEqual(self.bootstrap(token='wrong')[0],403)
  self.assertEqual(self.bootstrap()[0],429)
 def test_wsgi_login_cookie_csrf_and_data(self):
  self.bootstrap()
  with patch.object(server,'SECURE',True):
   code,headers,data=self.request('/api/login',{'email':'owner@madar.test','password':'StrongPassword123!'})
  self.assertEqual(code,200);cookie=next(v for k,v in headers if k=='Set-Cookie');self.assertIn('Secure',cookie);self.assertIn('HttpOnly',cookie)
  h={'HTTP_COOKIE':cookie.split(';')[0]};code,_,data=self.request('/api/me',headers=h);self.assertEqual(code,200);csrf=json.loads(data)['csrf']
  self.assertEqual(self.request('/api/companies',{'name':'شركة','contact':'مالك'},headers=h)[0],403)
  h['HTTP_X_CSRF_TOKEN']=csrf
  self.assertEqual(self.request('/api/companies',{'name':'شركة','contact':'مالك'},headers=h)[0],201)
  code,_,data=self.request('/api/companies',headers=h);self.assertEqual(code,200);self.assertEqual(json.loads(data)[0]['name'],'شركة')
 def test_wsgi_origin_and_method(self):
  self.assertEqual(self.request('/api/setup',{'token':'a'*48},headers={'HTTP_ORIGIN':'https://evil.test'})[0],403)
  self.assertEqual(self.request('/api/health',method='DELETE')[0],405)
 def test_static_assets_and_setup_page(self):
  for path,expected in [('/','text/html'),('/setup','text/html'),('/app.js','text/javascript'),('/styles.css','text/css')]:
   code,h,data=self.request(path);self.assertEqual(code,200);self.assertTrue(any(k=='Content-Type' and v.startswith(expected) for k,v in h));self.assertTrue(data)
 def test_body_size_limit(self):
  # Unknown users are never created from an oversized setup payload.
  self.assertEqual(self.bootstrap(name='x'*7_100_001)[0],413)
if __name__=='__main__':unittest.main()
