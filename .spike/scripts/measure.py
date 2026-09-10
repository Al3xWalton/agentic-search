import subprocess,sys,time,resource,json,os,datetime
from pathlib import Path
name=sys.argv[1]; cmd=sys.argv[2:]; root=Path(__file__).resolve().parents[1]
disk_path=os.environ.get('SPIKE_DISK_PATH')
def disk_bytes():
 if not disk_path:return None
 return sum(f.stat().st_size for f in Path(disk_path).rglob('*') if f.is_file()) if Path(disk_path).exists() else 0
disk_before=disk_bytes();disk_peak=disk_before
start=time.perf_counter(); stamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
with (root/'logs'/f'{name}.log').open('w') as out:
 p=subprocess.Popen(cmd,stdout=out,stderr=subprocess.STDOUT)
 print(f'{name}: pid={p.pid}',flush=True)
 if disk_path:
  while p.poll() is None:
   try:disk_peak=max(disk_peak,disk_bytes())
   except FileNotFoundError:pass
   time.sleep(1)
 rc=p.wait()
u=resource.getrusage(resource.RUSAGE_CHILDREN)
r={'name':name,'command':cmd,'cwd':os.getcwd(),'started_utc':stamp,'exit_code':rc,'wall_seconds':time.perf_counter()-start,'cpu_user_seconds':u.ru_utime,'cpu_system_seconds':u.ru_stime,'peak_rss_bytes':u.ru_maxrss if sys.platform=='darwin' else u.ru_maxrss*1024,'peak_rss_scope':'max child process RSS (not summed concurrent process tree)'}
if disk_path:
 disk_final=disk_bytes(); disk_peak=max(disk_peak,disk_final)
 r.update({'disk_path':disk_path,'disk_before_bytes':disk_before,'disk_final_bytes':disk_final,'disk_peak_sampled_bytes':disk_peak,'disk_sample_interval_seconds':1})
r.update({'block_input_operations':u.ru_inblock,'block_output_operations':u.ru_oublock})
(root/'logs'/f'{name}.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r),flush=True)
print((root/'logs'/f'{name}.log').read_text(errors='replace')[-6000:],flush=True)
sys.exit(rc)
