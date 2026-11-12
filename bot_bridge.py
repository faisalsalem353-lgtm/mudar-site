"""Integration adapter for a reviewed bot /start handler; no legacy database writes."""
import json,os,re
from urllib.parse import urlparse
from urllib.request import Request,urlopen

def link_mudar_account(start_payload,telegram_user_id):
 """Pass update.effective_user.id from Telegram, never a user-supplied ID."""
 if not isinstance(start_payload,str) or not re.fullmatch(r'm_[A-Za-z0-9_-]{43}',start_payload):return None
 origin=os.environ.get('MUDAR_PUBLIC_ORIGIN','').rstrip('/');secret=os.environ.get('MUDAR_BOT_BRIDGE_SECRET')
 parsed=urlparse(origin)
 if parsed.scheme!='https' or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or not secret:raise RuntimeError('Configure the verified HTTPS website and bridge secret')
 if not isinstance(telegram_user_id,int) or telegram_user_id<=0:raise ValueError('Telegram sender ID required')
 data=json.dumps({'token':start_payload[2:],'telegram_id':str(telegram_user_id)}).encode()
 req=Request(origin+'/api/bot/link',data=data,method='POST',headers={'Content-Type':'application/json','Authorization':'Bearer '+secret})
 with urlopen(req,timeout=10) as response:result=json.load(response)
 if result.get('linked') is not True or not isinstance(result.get('account_id'),str):raise RuntimeError('Website did not confirm account linking')
 return result['account_id']
