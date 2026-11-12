import hashlib,hmac,os,re,secrets,time,uuid
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse
from flask import Flask,request,jsonify,session,render_template,send_from_directory
from werkzeug.security import generate_password_hash,check_password_hash
from store import Store
from mailer import configured_mailer

ROOT=Path(__file__).parent
COOKIE='mudar_session'

def create_app(config=None):
 app=Flask(__name__,static_folder=None)
 app.config.update(SECRET_KEY=os.environ.get('MUDAR_SESSION_SECRET'),PRODUCTION=bool(os.environ.get('VERCEL')),DATABASE_URL=os.environ.get('MUDAR_DATABASE_URL') or os.environ.get('MUDAR_DATABASE_DATABASE_URL'),LOCAL_DB=os.environ.get('MUDAR_LOCAL_DB'),PUBLIC_ORIGIN=os.environ.get('MUDAR_PUBLIC_ORIGIN') or ('https://'+os.environ['VERCEL_URL'] if os.environ.get('VERCEL_ENV')=='preview' and os.environ.get('VERCEL_URL','').endswith('.vercel.app') else 'http://127.0.0.1:5180'),BOT_BRIDGE_SECRET=os.environ.get('MUDAR_BOT_BRIDGE_SECRET'),MAILER=configured_mailer(),BRIDGE_ENABLED=os.environ.get('MUDAR_BRIDGE_ENABLED')=='1',MAX_CONTENT_LENGTH=16384,SESSION_COOKIE_NAME=COOKIE,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',PERMANENT_SESSION_LIFETIME=86400)
 if config:app.config.update(config)
 prod=app.config['PRODUCTION'];secret=app.config['SECRET_KEY']
 if not secret or len(secret)<32:raise RuntimeError('MUDAR_SESSION_SECRET must contain at least 32 characters')
 app.config['SESSION_COOKIE_SECURE']=prod
 if prod and (not app.config['DATABASE_URL'] or not app.config['PUBLIC_ORIGIN'].startswith('https://')):raise RuntimeError('Production requires cloud PostgreSQL and an HTTPS origin')
 if not prod and not app.config['LOCAL_DB'] and not app.config['DATABASE_URL']:raise RuntimeError('Set MUDAR_LOCAL_DB explicitly for a development database')
 store=Store(app.config['DATABASE_URL'],app.config['LOCAL_DB']);app.extensions['store']=store
 # No startup migration, especially on serverless imports.
 def now():return int(time.time())
 def digest(value):return hashlib.sha256(value.encode()).hexdigest()
 def audit(q,event,uid=None):q.execute('INSERT INTO mudar_audit VALUES (?,?,?,?)',(str(uuid.uuid4()),uid,event,now()))
 def error(message,status=400):return jsonify(error=message),status
 def body():
  data=request.get_json(silent=True)
  return data if isinstance(data,dict) else {}
 def email(value):
  if not isinstance(value,str) or len(value)>254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',value):raise ValueError('أدخل بريدًا إلكترونيًا صحيحًا.')
  return value.strip().lower()
 def password(value):
  if not isinstance(value,str) or not 12<=len(value)<=128:raise ValueError('استخدم كلمة مرور من 12 إلى 128 حرفًا.')
  return value
 def limit(scope,maximum=10,window=900):
  key=hmac.new(secret.encode(),scope.encode(),hashlib.sha256).hexdigest()
  with store.transaction() as q:
   result=q.execute('INSERT INTO mudar_limits(scope,started,attempts) VALUES(?,?,1) ON CONFLICT(scope) DO UPDATE SET attempts=CASE WHEN mudar_limits.started<? THEN 1 ELSE mudar_limits.attempts+1 END, started=CASE WHEN mudar_limits.started<? THEN ? ELSE mudar_limits.started END RETURNING attempts',(key,now(),now()-window,now()-window,now())).fetchone()
   return result['attempts']<=maximum
 def account():
  uid=session.get('uid')
  if not uid:return None
  with store.transaction() as q:row=q.execute('SELECT * FROM mudar_accounts WHERE id=?',(uid,)).fetchone()
  if not row or row['auth_version']!=session.get('version'):session.clear();return None
  return dict(row)
 def protected(fn):
  @wraps(fn)
  def wrapper(*args,**kwargs):
   user=account()
   if not user:return error('سجّل الدخول للمتابعة.',401)
   return fn(user,*args,**kwargs)
  return wrapper
 def login(user):
  session.clear();session.update(uid=user['id'],version=user['auth_version'],csrf=secrets.token_urlsafe(32));session.permanent=True
 @app.before_request
 def security():
  if request.method in ('POST','PUT','DELETE','PATCH'):
   if request.path=='/api/bot/link':return
   if request.headers.get('Origin')!=app.config['PUBLIC_ORIGIN']:return error('مصدر الطلب غير مسموح.',403)
   supplied=request.headers.get('X-CSRF-Token','');expected=session.get('csrf','')
   if not supplied or not expected or not hmac.compare_digest(supplied,expected):return error('حدّث الصفحة وحاول مرة أخرى.',403)
 @app.after_request
 def headers(response):
  response.headers.update({'X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",'Permissions-Policy':'camera=(), microphone=(), geolocation=()'})
  if request.path.startswith('/api/') or request.path in ('/account','/login','/reset','/verify'):response.headers['Cache-Control']='no-store'
  if prod:response.headers['Strict-Transport-Security']='max-age=31536000'
  return response
 @app.errorhandler(413)
 def too_large(e):return error('حجم الطلب أكبر من المسموح.',413)
 @app.errorhandler(500)
 def failed(e):return error('تعذّر إكمال الطلب الآن. حاول لاحقًا.',503)
 @app.get('/health')
 def health():return jsonify(status='ok',service='mudar-unified',mode='production' if prod else 'development')
 @app.get('/health/ready')
 def readiness():
  database_ready=False
  try:
   with store.transaction() as q:
    for table in ('mudar_accounts','mudar_tokens','mudar_limits','mudar_audit'):q.execute('SELECT 1 FROM '+table+' LIMIT 0')
   database_ready=True
  except Exception:pass
  checks=dict(database=database_ready,verification_mail=bool(app.config['MAILER']),telegram_bridge=bool(app.config['BRIDGE_ENABLED'] and app.config['BOT_BRIDGE_SECRET']))
  return jsonify(ready=database_ready and checks['verification_mail'],checks=checks),200 if database_ready and checks['verification_mail'] else 503
 @app.get('/')
 @app.get('/login')
 @app.get('/account')
 @app.get('/reset')
 @app.get('/verify')
 def page():return render_template('index.html',development=not prod)
 @app.get('/assets/<path:name>')
 def assets(name):return send_from_directory(ROOT/'public'/'assets',name)
 @app.get('/api/session')
 def current():
  user=account();session.setdefault('csrf',secrets.token_urlsafe(32))
  return jsonify(csrf=session['csrf'],user={k:user[k] for k in ('id','name','email','phone','telegram_id')} if user else None,recovery_available=bool(app.config['MAILER']),bridge_available=bool(app.config['BRIDGE_ENABLED'] and app.config['BOT_BRIDGE_SECRET']))
 @app.post('/api/auth/register')
 def register():
  d=body()
  if prod and not app.config['MAILER']:return error('إنشاء الحسابات غير متاح حتى تفعيل بريد التحقق.',503)
  try:
   address=email(d.get('email'));pw=password(d.get('password'));name=d.get('name','');phone=d.get('phone','')
   if not isinstance(name,str) or not 2<=len(name.strip())<=100 or any(ord(c)<32 for c in name):raise ValueError('أدخل اسمك الكامل بشكل صحيح.')
   if not isinstance(phone,str):raise ValueError('أدخل رقم جوال سعوديًا صحيحًا.')
   phone=phone.translate(str.maketrans('٠١٢٣٤٥٦٧٨٩','0123456789'));phone=re.sub(r'[\s()-]','',phone).replace('00966','+966')
   if phone.startswith('+966'):phone='0'+phone[4:]
   if not re.fullmatch(r'05[0-9]{8}',phone):raise ValueError('أدخل رقم جوال سعوديًا صحيحًا.')
  except ValueError as e:return error(str(e))
  if not limit('register:'+str(request.remote_addr),5,3600):return error('محاولات كثيرة. حاول لاحقًا.',429)
  uid=str(uuid.uuid4());hashed=generate_password_hash(pw,method='scrypt')
  with store.transaction() as q:
   row=q.execute('INSERT INTO mudar_accounts(id,email,name,phone,password_hash,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(email) DO NOTHING RETURNING id',(uid,address,name.strip(),phone,hashed,now())).fetchone()
   if not row:return error('تعذّر إنشاء الحساب بهذه البيانات. جرّب الدخول أو استعادة الوصول.',409)
   audit(q,'account.created',uid)
  if prod:
   try:send_verification(uid,address)
   except Exception:return error('أُنشئ الحساب وتعذّر إرسال التحقق. أعد طلب رسالة التحقق.',503)
   return jsonify(ok=True,verification_required=True,message='أرسلنا رابط تأكيد بريدك. افتحه قبل تسجيل الدخول.'),201
  login(dict(id=uid,auth_version=1));return jsonify(ok=True),201
 @app.post('/api/auth/login')
 def signin():
  d=body()
  try:address=email(d.get('email'));pw=password(d.get('password'))
  except ValueError:return error('بيانات الدخول غير صحيحة.',401)
  if not limit('login:'+address) or not limit('login-ip:'+str(request.remote_addr),50):return error('محاولات كثيرة. حاول بعد 15 دقيقة.',429)
  with store.transaction() as q:user=q.execute('SELECT * FROM mudar_accounts WHERE email=?',(address,)).fetchone()
  if not check_password_hash(user['password_hash'] if user else app.config['DUMMY_HASH'],pw):return error('بيانات الدخول غير صحيحة.',401)
  if prod and not user['email_verified']:return error('أكّد بريدك الإلكتروني قبل تسجيل الدخول.',403)
  login(user)
  with store.transaction() as q:audit(q,'account.login',user['id'])
  return jsonify(ok=True)
 @app.post('/api/auth/logout')
 def logout():session.clear();return jsonify(ok=True)
 def send_verification(uid,address):
  token=secrets.token_urlsafe(32)
  with store.transaction() as q:
   q.execute('UPDATE mudar_tokens SET used_at=? WHERE account_id=? AND purpose=? AND used_at IS NULL',(now(),uid,'verify'))
   q.execute('INSERT INTO mudar_tokens VALUES(?,?,?,?,NULL)',(digest(token),uid,'verify',now()+1800))
  app.config['MAILER'](address,app.config['PUBLIC_ORIGIN']+'/verify#token='+token)
 @app.post('/api/auth/resend')
 def resend():
  if not app.config['MAILER']:return error('بريد التحقق غير مفعّل بعد.',503)
  try:address=email(body().get('email'))
  except ValueError as e:return error(str(e))
  if not limit('verify:'+address,3,3600) or not limit('verify-ip:'+str(request.remote_addr),15,3600):return error('محاولات كثيرة. حاول لاحقًا.',429)
  with store.transaction() as q:row=q.execute('SELECT id,email_verified FROM mudar_accounts WHERE email=?',(address,)).fetchone()
  if row and not row['email_verified']:
   try:send_verification(row['id'],address)
   except Exception:return error('تعذّر إرسال التحقق. حاول لاحقًا.',503)
  return jsonify(message='إذا كان الحساب بحاجة إلى تحقق، ستصلك رسالة تأكيد.')
 @app.post('/api/auth/verify')
 def verify():
  token=body().get('token')
  if not isinstance(token,str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',token):return error('رابط التحقق غير صالح.')
  if not limit('verify-token:'+str(request.remote_addr),20):return error('محاولات كثيرة. حاول لاحقًا.',429)
  with store.transaction() as q:
   row=q.execute('UPDATE mudar_tokens SET used_at=? WHERE digest=? AND purpose=? AND used_at IS NULL AND expires_at>? RETURNING account_id',(now(),digest(token),'verify',now())).fetchone()
   if not row:return error('رابط التحقق مستخدم أو انتهت صلاحيته.')
   q.execute('UPDATE mudar_accounts SET email_verified=1 WHERE id=?',(row['account_id'],));audit(q,'email.verified',row['account_id'])
  return jsonify(ok=True)
 @app.post('/api/auth/recover')
 def recover():
  # No tokens returned in API responses or logs. Delivery must be configured server-side.
  if not app.config['MAILER']:return error('استعادة كلمة المرور غير متاحة بعد. لم تُرسل رسالة.',503)
  try:address=email(body().get('email'))
  except ValueError as e:return error(str(e))
  if not limit('recover:'+address,3,3600) or not limit('recover-ip:'+str(request.remote_addr),15,3600):return error('محاولات كثيرة. حاول لاحقًا.',429)
  with store.transaction() as q:
   row=q.execute('SELECT id FROM mudar_accounts WHERE email=?',(address,)).fetchone()
   if row:
    token=secrets.token_urlsafe(32)
    q.execute('UPDATE mudar_tokens SET used_at=? WHERE account_id=? AND purpose=? AND used_at IS NULL',(now(),row['id'],'reset'))
    q.execute('INSERT INTO mudar_tokens VALUES(?,?,?,?,NULL)',(digest(token),row['id'],'reset',now()+1800));audit(q,'recovery.requested',row['id'])
  if row:
   try:app.config['MAILER'](address,app.config['PUBLIC_ORIGIN']+'/reset#token='+token)
   except Exception:return error('تعذّر إرسال رسالة الاستعادة. حاول لاحقًا.',503)
  return jsonify(message='إذا كان البريد مسجّلًا، ستصلك رسالة لاستعادة الوصول.')
 @app.post('/api/auth/reset')
 def reset():
  d=body();token=d.get('token','')
  try:pw=password(d.get('password'))
  except ValueError as e:return error(str(e))
  if not isinstance(token,str) or len(token)>128:return error('الرابط غير صالح أو انتهت صلاحيته.')
  if not limit('reset-ip:'+str(request.remote_addr),20):return error('محاولات كثيرة. حاول لاحقًا.',429)
  hashed=generate_password_hash(pw,method='scrypt')
  with store.transaction() as q:
   row=q.execute('UPDATE mudar_tokens SET used_at=? WHERE digest=? AND purpose=? AND used_at IS NULL AND expires_at>? RETURNING account_id',(now(),digest(token),'reset',now())).fetchone()
   if not row:return error('الرابط غير صالح أو انتهت صلاحيته.')
   q.execute('UPDATE mudar_accounts SET password_hash=?,auth_version=auth_version+1 WHERE id=?',(hashed,row['account_id']))
   q.execute('UPDATE mudar_tokens SET used_at=? WHERE account_id=? AND used_at IS NULL',(now(),row['account_id']));audit(q,'password.reset',row['account_id'])
  session.clear();return jsonify(ok=True)
 @app.post('/api/telegram/token')
 @protected
 def issue_link(user):
  if not app.config['BRIDGE_ENABLED'] or not app.config['BOT_BRIDGE_SECRET']:return error('ربط البوت غير مفعّل بعد. حسابك محفوظ.',503)
  if user['telegram_id']:return error('الحساب مرتبط بـTelegram بالفعل.',409)
  if not limit('link:'+user['id'],5):return error('محاولات كثيرة. حاول لاحقًا.',429)
  token=secrets.token_urlsafe(32)
  with store.transaction() as q:
   q.execute('UPDATE mudar_tokens SET used_at=? WHERE account_id=? AND purpose=? AND used_at IS NULL',(now(),user['id'],'telegram'))
   q.execute('INSERT INTO mudar_tokens VALUES(?,?,?,?,NULL)',(digest(token),user['id'],'telegram',now()+600));audit(q,'telegram.token_issued',user['id'])
  return jsonify(url='https://t.me/Medar_App_bot?start=m_'+token,expiresIn=600)
 @app.post('/api/bot/link')
 def link():
  bridge=app.config['BOT_BRIDGE_SECRET']
  if not app.config['BRIDGE_ENABLED'] or not bridge or not hmac.compare_digest(request.headers.get('Authorization',''),'Bearer '+bridge):return error('غير مسموح.',401)
  d=body();token=d.get('token');tid=str(d.get('telegram_id',''))
  if not isinstance(token,str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',token) or not re.fullmatch(r'[1-9][0-9]{0,18}',tid):return error('بيانات ربط غير صحيحة.')
  try:
   with store.transaction() as q:
    row=q.execute('UPDATE mudar_tokens SET used_at=? WHERE digest=? AND purpose=? AND used_at IS NULL AND expires_at>? RETURNING account_id',(now(),digest(token),'telegram',now())).fetchone()
    if not row:return error('رمز الربط غير صالح أو مستخدم.')
    updated=q.execute('UPDATE mudar_accounts SET telegram_id=? WHERE id=? AND telegram_id IS NULL RETURNING id',(tid,row['account_id'])).fetchone()
    if not updated:raise ValueError('link-conflict')
    audit(q,'telegram.linked',row['account_id'])
   return jsonify(account_id=row['account_id'],linked=True)
  except Exception:
   # Roll back token consumption on conflicts. No account data or DB details leaked.
   return error('الحساب مرتبط مسبقًا أو تعذّر الربط.',409)
 app.config['DUMMY_HASH']=generate_password_hash(secrets.token_urlsafe(24),method='scrypt')
 return app

if __name__=='__main__':
 app=create_app()
 app.run(host='127.0.0.1',port=5180,debug=False)
elif os.environ.get('VERCEL'):
 app=create_app()
