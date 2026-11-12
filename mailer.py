"""SMTP delivery configured only through environment; never logs links or credentials."""
import os,ssl,smtplib
from email.message import EmailMessage

def configured_mailer():
 host=os.environ.get('MUDAR_SMTP_HOST');user=os.environ.get('MUDAR_SMTP_USER');password=os.environ.get('MUDAR_SMTP_PASSWORD');sender=os.environ.get('MUDAR_SMTP_FROM')
 if not all((host,user,password,sender)):return None
 port=int(os.environ.get('MUDAR_SMTP_PORT','465'))
 def deliver(recipient,url):
  msg=EmailMessage();msg['From']=sender;msg['To']=recipient
  verify='/verify#' in url
  msg['Subject']='تأكيد بريدك في مُدار' if verify else 'استعادة الوصول إلى مُدار'
  msg.set_content(('لتأكيد بريدك الإلكتروني' if verify else 'لتعيين كلمة مرور جديدة')+'، افتح الرابط التالي:\n'+url+'\n\nإذا لم تطلب هذه الرسالة، تجاهلها. لا تشارك الرابط مع أي شخص.')
  if port==465:
   with smtplib.SMTP_SSL(host,port,timeout=10,context=ssl.create_default_context()) as smtp:
    smtp.login(user,password);smtp.send_message(msg)
  else:
   with smtplib.SMTP(host,port,timeout=10) as smtp:
    smtp.ehlo();smtp.starttls(context=ssl.create_default_context());smtp.ehlo();smtp.login(user,password);smtp.send_message(msg)
 return deliver
