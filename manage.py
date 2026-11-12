"""Explicit schema creation. Does not run during app import or deployment."""
import argparse,os
from app import create_app
p=argparse.ArgumentParser();p.add_argument('command',choices=['init-local','init-cloud']);p.add_argument('--approved-new-database',action='store_true');args=p.parse_args()
if args.command=='init-local' and (os.environ.get('VERCEL') or os.environ.get('MUDAR_DATABASE_URL')):p.error('Local initialization cannot target a cloud database')
if args.command=='init-cloud' and not (args.approved_new_database and os.environ.get('MUDAR_DATABASE_URL')):p.error('Cloud schema creation requires a separately approved new database')
app=create_app();app.extensions['store'].initialize();print('Initialized isolated mudar account tables')
