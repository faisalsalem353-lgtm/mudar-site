"""Isolated account store. Never imports or migrates legacy medar tables."""
import sqlite3
from urllib.parse import urlparse,parse_qs,unquote
from contextlib import contextmanager

SCHEMA = '''
CREATE TABLE IF NOT EXISTS mudar_accounts (
 id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
 phone TEXT NOT NULL, password_hash TEXT NOT NULL, auth_version INTEGER NOT NULL DEFAULT 1,
 created_at BIGINT NOT NULL, telegram_id TEXT UNIQUE, email_verified INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS mudar_tokens (
 digest TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES mudar_accounts(id),
 purpose TEXT NOT NULL, expires_at BIGINT NOT NULL, used_at BIGINT
);
CREATE TABLE IF NOT EXISTS mudar_limits (scope TEXT PRIMARY KEY, started BIGINT NOT NULL, attempts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS mudar_audit (id TEXT PRIMARY KEY, account_id TEXT, event TEXT NOT NULL, created_at BIGINT NOT NULL);
'''

class Store:
 def __init__(self, url=None, path=None):
  if url:
   parsed=urlparse(url)
   if parsed.scheme not in ('postgres','postgresql'):raise ValueError('PostgreSQL connection URL required')
   if unquote(parsed.path.lstrip('/')) in ('medar','medar_next'):raise ValueError('Legacy databases are not allowed for this isolated account service')
   if parse_qs(parsed.query).get('sslmode',[''])[0] not in ('require','verify-ca','verify-full'):raise ValueError('Cloud database TLS is required')
  self.url,self.path=url,path
 @contextmanager
 def transaction(self):
  if self.url:
   import psycopg2
   from psycopg2.extras import RealDictCursor
   conn=psycopg2.connect(self.url,connect_timeout=5,cursor_factory=RealDictCursor)
  else:
   conn=sqlite3.connect(self.path,timeout=10);conn.row_factory=sqlite3.Row
   conn.execute('PRAGMA foreign_keys=ON')
  try:
   yield Query(conn,bool(self.url));conn.commit()
  except Exception:
   conn.rollback();raise
  finally: conn.close()
 def initialize(self):
  with self.transaction() as q:
   for statement in SCHEMA.split(';'):
    if statement.strip():q.execute(statement)

class Query:
 def __init__(self,conn,pg):self.conn,self.pg=conn,pg
 def execute(self,sql,params=()):
  cursor=self.conn.cursor();cursor.execute(sql.replace('?', '%s') if self.pg else sql,params);return cursor
