#!/usr/bin/env python3
"""Start the local console; keep its access token in a private runtime directory."""
import argparse
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main():
    p=argparse.ArgumentParser(description="Start Sentinel-ZT-CTTR on localhost")
    p.add_argument('--port',type=int,default=8000)
    p.add_argument('--no-print-token',action='store_true',help='keep the bearer token out of service logs')
    args=p.parse_args()
    if not 1024 <= args.port <= 65535:
        p.error('port must be in 1024..65535')
    os.chdir(ROOT)
    data=Path(os.environ.get('SENTINEL_DATA_DIR',ROOT/'.sentinel-data'))
    data.mkdir(mode=0o700,parents=True,exist_ok=True)
    keyfile=data/'access-token'
    if not os.environ.get('SENTINEL_API_TOKEN'):
        if not keyfile.exists():
            fd=os.open(keyfile,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as f:f.write(secrets.token_hex(32))
        os.environ['SENTINEL_API_TOKEN']=keyfile.read_text().strip()
    os.environ['SENTINEL_DATA_DIR']=str(data)
    if os.environ.get('SENTINEL_DEPLOYMENT_MODE','local')=='local':
        os.environ['SENTINEL_ALLOWED_ORIGINS']=f'http://127.0.0.1:{args.port},http://localhost:{args.port}'
    from sentinel_zt.deployment import settings
    deployment=settings()
    if not (ROOT/'web'/'dist'/'index.html').exists():
        raise SystemExit('Build frontend first: cd web && npm ci && npm run build')
    try:
        import uvicorn
    except ImportError:
        raise SystemExit('Install web dependencies: python -m pip install -r requirements-web.txt')
    print(f'\nSentinel-ZT-CTTR: http://127.0.0.1:{args.port}',flush=True)
    if deployment['public_origin']:
        print('Configured application origin: '+deployment['public_origin'],flush=True)
        print('Cloud connectivity and policy enforcement still require tenant validation.',flush=True)
    if not args.no_print_token and deployment['mode']=='local':
        print('Paste this local access token into the console:',flush=True)
        print(os.environ['SENTINEL_API_TOKEN'],flush=True)
    else:
        print('Access token hidden from service logs; use the configured secret or private access-token file.',flush=True)
    print('Keep this token private. Press Ctrl+C to stop.\n',flush=True)
    uvicorn.run('sentinel_zt.api:create_app',factory=True,host='127.0.0.1',port=args.port,access_log=False,proxy_headers=False)


if __name__=='__main__':main()
