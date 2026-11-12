import hashlib,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import create_app

class Accounts(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.sent=[]
  self.app=create_app(dict(TESTING=True,SECRET_KEY='test-secret-'+'x'*40,PRODUCTION=False,LOCAL_DB=str(Path(self.temp.name)/'test.sqlite3'),DATABASE_URL=None,PUBLIC_ORIGIN='http://localhost',MAILER=lambda address,url:self.sent.append((address,url)),BOT_BRIDGE_SECRET='test-bridge-'+'z'*40,BRIDGE_ENABLED=True))
  self.app.extensions['store'].initialize();self.client=self.app.test_client()
 def tearDown(self):self.temp.cleanup()
 def csrf(self,client=None):return (client or self.client).get('/api/session').json['csrf']
 def post(self,url,data,client=None):
  c=client or self.client
  return c.post(url,json=data,headers={'Origin':'http://localhost','X-CSRF-Token':self.csrf(c)})
 def signup(self,client=None,address='one@example.test'):
  return self.post('/api/auth/register',dict(name='فيصل العمري',email=address,phone='٠٥٥١٢٣٤٥٦٧',password='a very private password'),client)
 def test_signup_and_session(self):
  self.assertEqual(self.signup().status_code,201);user=self.client.get('/api/session').json['user'];self.assertEqual(user['phone'],'0551234567');self.assertNotIn('password_hash',user)
  with self.app.extensions['store'].transaction() as q:
   row=q.execute('SELECT password_hash FROM mudar_accounts').fetchone();self.assertTrue(row['password_hash'].startswith('scrypt:'));self.assertNotIn('a very private password',row['password_hash'])
 def test_csrf_and_origin(self):
  self.assertEqual(self.client.post('/api/auth/register',json={}).status_code,403)
  self.assertEqual(self.client.post('/api/auth/logout',json={},headers={'Origin':'https://evil.test','X-CSRF-Token':self.csrf()}).status_code,403)
 def test_duplicate_and_bad_input(self):
  self.signup();self.assertEqual(self.signup().status_code,409)
  self.assertEqual(self.post('/api/auth/register',dict(name='a',email='bad',phone='wrong',password='short')).status_code,400)
 def test_login_logout(self):
  self.signup();self.post('/api/auth/logout',{});self.assertIsNone(self.client.get('/api/session').json['user'])
  self.assertEqual(self.post('/api/auth/login',dict(email='one@example.test',password='wrong but sufficiently long')).status_code,401)
  self.assertEqual(self.post('/api/auth/login',dict(email='ONE@example.test',password='a very private password')).status_code,200)
 def test_user_isolation(self):
  self.signup();second=self.app.test_client();self.signup(second,'two@example.test')
  self.assertNotEqual(self.client.get('/api/session').json['user']['id'],second.get('/api/session').json['user']['id'])
 def test_reset_single_use_and_session_revocation(self):
  self.signup();self.post('/api/auth/recover',dict(email='one@example.test'));token=self.sent[0][1].split('#token=')[1]
  other=self.app.test_client();payload=dict(token=token,password='a different private password')
  self.assertEqual(self.post('/api/auth/reset',payload,other).status_code,200)
  self.assertIsNone(self.client.get('/api/session').json['user'])
  self.assertEqual(self.post('/api/auth/reset',payload,other).status_code,400)
  self.assertEqual(self.post('/api/auth/login',dict(email='one@example.test',password='a very private password'),other).status_code,401)
  self.assertEqual(self.post('/api/auth/login',dict(email='one@example.test',password='a different private password'),other).status_code,200)
 def test_recovery_does_not_disclose_token_or_unknown_account(self):
  self.signup();known=self.post('/api/auth/recover',dict(email='one@example.test'));unknown=self.post('/api/auth/recover',dict(email='unknown@example.test'))
  self.assertEqual(known.json,unknown.json);self.assertEqual(len(self.sent),1);self.assertNotIn('token',str(known.json))
 def test_disabled_recovery_is_honest(self):
  self.app.config['MAILER']=None;self.assertEqual(self.post('/api/auth/recover',dict(email='one@example.test')).status_code,503)
 def test_link_requires_login_and_bridge_authority(self):
  self.assertEqual(self.post('/api/telegram/token',{}).status_code,401);self.signup()
  self.assertEqual(self.client.post('/api/bot/link',json={}).status_code,401)
 def issue(self):return self.post('/api/telegram/token',{}).json['url'].split('start=m_')[1]
 def consume(self,token,tid='1234'):
  return self.client.post('/api/bot/link',json={'token':token,'telegram_id':tid},headers={'Authorization':'Bearer '+self.app.config['BOT_BRIDGE_SECRET']})
 def test_link_once_and_hashed_at_rest(self):
  self.signup();token=self.issue()
  with self.app.extensions['store'].transaction() as q:
   row=q.execute('SELECT digest FROM mudar_tokens').fetchone();self.assertEqual(row['digest'],hashlib.sha256(token.encode()).hexdigest())
  self.assertEqual(self.consume(token).status_code,200);self.assertEqual(self.consume(token).status_code,400);self.assertEqual(self.client.get('/api/session').json['user']['telegram_id'],'1234')
 def test_new_link_revokes_old_and_expiry(self):
  self.signup();old=self.issue();new=self.issue();self.assertEqual(self.consume(old).status_code,400)
  with self.app.extensions['store'].transaction() as q:q.execute('UPDATE mudar_tokens SET expires_at=0')
  self.assertEqual(self.consume(new).status_code,400)
 def test_telegram_cannot_link_two_accounts(self):
  self.signup();self.consume(self.issue());other=self.app.test_client();self.signup(other,'two@example.test');token=self.post('/api/telegram/token',{},other).json['url'].split('start=m_')[1]
  self.assertEqual(self.consume(token).status_code,409)
  self.assertEqual(self.consume(token,'5678').status_code,200) # Failed consumption must roll back.
 def test_bridge_disabled_by_default(self):
  self.signup();self.app.config['BRIDGE_ENABLED']=False;self.assertEqual(self.post('/api/telegram/token',{}).status_code,503)
 def test_rate_limit(self):
  self.signup()
  for _ in range(10):self.post('/api/auth/login',dict(email='one@example.test',password='wrong but sufficiently long'))
  self.assertEqual(self.post('/api/auth/login',dict(email='one@example.test',password='a very private password')).status_code,429)
 def test_no_user_trusted_auth_headers(self):
  self.assertIsNone(self.client.get('/api/session',headers={'oai-authenticated-user-id':'victim','oai-authenticated-user-email':'victim@example.test'}).json['user'])
 def test_security_headers(self):
  r=self.client.get('/api/session');self.assertEqual(r.headers['Cache-Control'],'no-store');self.assertIn("frame-ancestors 'none'",r.headers['Content-Security-Policy']);self.assertIn('HttpOnly',r.headers['Set-Cookie'])
 def test_explicit_init_and_production_guards(self):
  with self.assertRaises(RuntimeError):create_app(dict(SECRET_KEY='short'))
  with self.assertRaises(RuntimeError):create_app(dict(SECRET_KEY='x'*40,PRODUCTION=True,DATABASE_URL=None))
 def test_verification_single_use(self):
  self.signup();self.post('/api/auth/resend',dict(email='one@example.test'));token=self.sent[0][1].split('#token=')[1]
  self.assertEqual(self.post('/api/auth/verify',dict(token=token)).status_code,200)
  self.assertEqual(self.post('/api/auth/verify',dict(token=token)).status_code,400)
 def test_schema_not_initialized_on_import(self):
  p=Path(self.temp.name)/'not-created.sqlite3';create_app(dict(SECRET_KEY='x'*40,PRODUCTION=False,LOCAL_DB=str(p),DATABASE_URL=None));self.assertFalse(p.exists())

 def test_legacy_cloud_database_and_unencrypted_urls_rejected(self):
  from store import Store
  for url in ['postgresql://localhost/medar?sslmode=require','postgresql://localhost/medar_next?sslmode=require','postgresql://localhost/new_database']:
   with self.assertRaises(ValueError):Store(url)
 def test_production_verification_policy(self):
  prod=create_app(dict(TESTING=True,SECRET_KEY='x'*40,PRODUCTION=True,DATABASE_URL='postgresql://localhost/isolated_test?sslmode=require',LOCAL_DB=str(Path(self.temp.name)/'prod.sqlite3'),PUBLIC_ORIGIN='https://example.test',MAILER=lambda address,url:self.sent.append((address,url))))
  # Exercise production policy against a disposable SQLite adapter; no PostgreSQL connection.
  prod.extensions['store'].url=None;prod.extensions['store'].initialize();prod.config['PUBLIC_ORIGIN']='http://localhost'
  c=prod.test_client()
  def post(path,data):
   token=c.get('/api/session').json['csrf']
   return c.post(path,json=data,headers={'Origin':'http://localhost','X-CSRF-Token':token})
  r=post('/api/auth/register',dict(name='Test Owner',phone='0551234567',email='prod@example.test',password='a very private password'));self.assertTrue(r.json['verification_required'])
  self.assertIsNone(c.get('/api/session').json['user'])
  self.assertEqual(post('/api/auth/login',dict(email='prod@example.test',password='a very private password')).status_code,403)
  token=self.sent[-1][1].split('#token=')[1];self.assertEqual(post('/api/auth/verify',dict(token=token)).status_code,200)
  self.assertEqual(post('/api/auth/login',dict(email='prod@example.test',password='a very private password')).status_code,200)
  self.assertIn('Secure',c.get('/api/session').headers['Set-Cookie'])

if __name__=='__main__':unittest.main()
