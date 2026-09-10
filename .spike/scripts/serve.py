import subprocess,sys,json,os,signal,socket,time
from pathlib import Path
root=Path(__file__).resolve().parents[1]; repo=root.parent; manifest=root/'data/server-processes.json'; binary=str(root/'target-1.98/release/stract')
if sys.argv[1]=='start':
 assert not manifest.exists(),'server manifest exists'
 for port in [57300,57301,57302,57303,57305,57306,57307,57311]:
  with socket.socket() as s:s.bind(('127.0.0.1',port))
 procs=[]
 for name,mode,config in [('cc','search-server','search-cc.toml'),('seeds','search-server','search-seeds.toml'),('api','api','api.toml')]:
  cmd=[binary,mode,str(root/'configs'/config)]
  env=os.environ.copy();env['TMPDIR']=str(root/'tmp');env['RUST_LOG']='stract=info'
  with (root/'logs'/f'server-{name}.log').open('w') as log:
   p=subprocess.Popen(cmd,cwd=repo,env=env,stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,start_new_session=True)
  procs.append({'name':name,'pid':p.pid,'command':cmd});manifest.write_text(json.dumps(procs,indent=2)+'\n')
 print(json.dumps(procs,indent=2))
else:
 records=json.loads(manifest.read_text()) if manifest.exists() else []
 for rec in records:
  chk=subprocess.run(['ps','-p',str(rec['pid']),'-o','command='],capture_output=True,text=True)
  if binary in chk.stdout and rec['command'][2] in chk.stdout:
   os.kill(rec['pid'],signal.SIGTERM);print('terminated',rec['name'],rec['pid'])
  else:print('already exited or identity differs; not signalled',rec['name'],rec['pid'])
 (root/'data/server-cleanup.json').write_text(json.dumps({'requested_stop':records},indent=2)+'\n')
