"""nvlx 1.6 live Kubernetes operator daemon."""
from __future__ import annotations
import argparse, os
from pathlib import Path
from .k8s_api_v16 import KubeClient
from .lease_v16 import LeaseElector
from .nvidia_checkpoint_v1651 import LeaseCheckpointStore
from .nvidia_inventory_v1631 import NvidiaInventory
from .runtime_v1664 import Runtime
from .http_v166666666633112345675678512344565672 import HealthServer

def _read_token_file(path: str) -> str:
    token=Path(path).read_text(encoding="utf-8").strip()
    if not token: raise ValueError("token file is empty")
    return token

def main(argv=None):
    p=argparse.ArgumentParser(prog="nvlx-operator",description="nvlx 1.6 live GPUFleet Kubernetes operator")
    p.add_argument("--server",help="Kubernetes API URL; defaults to in-cluster configuration")
    auth=p.add_mutually_exclusive_group(); auth.add_argument("--token"); auth.add_argument("--token-file",help="read Kubernetes bearer token from a file instead of process arguments")
    p.add_argument("--namespace",default=os.environ.get("NVLX_NAMESPACE","nvlx-system")); p.add_argument("--identity",default=os.environ.get("POD_NAME") or os.environ.get("HOSTNAME") or "nvlx-controller")
    p.add_argument("--health-host",default="0.0.0.0"); p.add_argument("--health-port",type=int,default=8080); p.add_argument("--timeout",type=float,default=10.0)
    p.add_argument("--watch-timeout",type=float,default=25.0); p.add_argument("--watch-timeout-seconds",type=int,default=20); p.add_argument("--once",action="store_true")
    a=p.parse_args(argv); token=a.token
    if a.token_file:
        try: token=_read_token_file(a.token_file)
        except (OSError,ValueError) as e: p.error(f"cannot read --token-file: {e}")
    if not a.server and (a.token or a.token_file): p.error("--token/--token-file require --server; in-cluster mode uses the service-account token")
    kwargs={"timeout":a.timeout,"watch_timeout":a.watch_timeout,"watch_timeout_seconds":a.watch_timeout_seconds}
    client=KubeClient(a.server,token=token,**kwargs) if a.server else KubeClient.in_cluster(**kwargs)
    elector=LeaseElector(client,a.identity,namespace=a.namespace); inventory=NvidiaInventory(client)
    runtime=Runtime(client,a.identity,namespace=a.namespace,leader_check=elector.ensure_leader,leader_fresh_seconds=25.0)
    runtime.nvidia_inventory_check=inventory.check
    runtime.nvidia_checkpoint_store=LeaseCheckpointStore(client,a.identity,namespace=a.namespace,lease_name=elector.name)
    server=HealthServer(runtime,a.health_host,a.health_port).start()
    try:
        if a.once: runtime.list_and_watch_once(); return 0
        runtime.run_forever(); return 0
    finally: server.close()

if __name__=="__main__": raise SystemExit(main())
