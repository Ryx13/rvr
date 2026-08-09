"""RVR — NFS module"""
from typing import Dict, Any
from datetime import datetime
from rvr.modules.base import BaseModule
from rvr.utils.console import log_success, log_warn, console
from rvr.utils.state import RVRState

class NFSModule(BaseModule):
    def __init__(self, state: RVRState, profile: Dict[str, Any]):
        super().__init__(state, profile)
        self.nfs_dir = self.ensure_dir("nfs")

    def run(self):
        if not self.tool_exists(self.tool("showmount")):
            log_warn("showmount not found")
            return
        console.print("  [cyan]○[/cyan]  NFS mount enumeration...", end="\r")
        t0 = datetime.now()
        out_file = self.nfs_dir / "showmount.txt"
        output = self.run_command([self.tool("showmount"), "-e", self.state.target],
                                   output_file=out_file, timeout=30, silent=True)
        elapsed = (datetime.now() - t0).seconds
        if output:
            mounts = [l.strip().split()[0] for l in output.splitlines() if l.strip().startswith("/")]
            self.state.nfs_mounts.extend(mounts)
            console.print(f"  [green]✓[/green]  NFS — {len(mounts)} mount(s) found  [dim]({elapsed}s)[/dim]")
            if mounts:
                for m in mounts:
                    log_success(f"  Mount: {m}")
            self.state.add_artifact("nfs_mounts", out_file)
        else:
            console.print("  [dim]✗  NFS — no response[/dim]")
        rpc_out = self.nfs_dir / "rpcinfo.txt"
        self.run_command([self.tool("rpcinfo"), "-p", self.state.target],
                         output_file=rpc_out, timeout=30, silent=True)
        self.state.add_artifact("rpcinfo", rpc_out)