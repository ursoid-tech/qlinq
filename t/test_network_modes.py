from pathlib import Path
import subprocess, tempfile
app='./qlinq-app'
with tempfile.TemporaryDirectory(prefix='qlinq-mode-smoke-') as d:
    root=Path(d)
    payload=bytes(range(256))*200
    (root/'input').write_bytes(payload)
    for mode, receivers, gateway, port in [('p2p',1,False,10380), ('multicast-fanout',2,False,10381), ('multicast-fanout',1,True,10382)]:
        common=['--network-mode',mode,'--auth-token','smoke','--insecure-no-verify','--mode','rateless','--drain-ms','100']
        source=[app,*common,'--listen',str(port),'--bind','127.0.0.1','--cert','t/assets/server.crt','--key','t/assets/server.key','--input',str(root/'input'),'--message-size','512','--count','100','--wait-subscribers',str(receivers),'--interval-ms','10','--one-shot']
        if mode != 'p2p':
            source += ['--group','232.42.42.11','--group-port',str(port+100),'--group-interface','127.0.0.1']
        processes=[]
        logs=[]
        try:
            log=(root/f'{port}-source.log').open('wb');logs.append(log)
            processes.append(subprocess.Popen(source,stderr=log))
            for i in range(receivers):
                target=root/f'{port}-{i}.bin'
                command=[app,*common,'--peer',f'127.0.0.1:{port}','--output',str(target),'--receive-count','100']
                if mode != 'p2p':
                    command += ['--amt-relay','127.0.0.1','--amt-port','10399'] if gateway else ['--group-interface','127.0.0.1']
                log=(root/f'{port}-{i}.log').open('wb');logs.append(log)
                processes.append(subprocess.Popen(command,stderr=log))
            for process in processes:
                assert process.wait(timeout=10)==0
            for i in range(receivers):
                assert (root/f'{port}-{i}.bin').read_bytes()==payload
            print(mode, 'gateway-fallback' if gateway else 'native', receivers, 'receiver(s): PASS')
        except Exception:
            for p in processes:
                if p.poll() is None: p.kill()
            for f in root.glob(f'{port}*.log'):
                print(f.name,f.read_text())
            raise
        finally:
            for log in logs:log.close()

print("===NETWORK MODE CLI OK===")
