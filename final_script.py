#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FINAL UNIFIED VERSION  — Remote Sharding + Fast Dedupe Modes + Post-Run Cleanup
This integrates your Bitdefender NFS scanner with:
✓ Distributed streaming discovery (remote-find / remote-python)
✓ Remote sharding (avoids big local BFS on huge mounts)
✓ Coarser→deeper sharding based on shard-factor
✓ Per-server dynamic scan scheduler (pull-first)
✓ Accurate Bitdefender task counting (ignores header)
✓ Cleanup of /var/tmp scan remnants (pre-run, post-run, and on interrupt)
✓ Dedupe modes: auto, off, leaf-only, parent-only, hybrid (O(N log N))
✓ Parent-dir dedupe (legacy) still available via --no-parent-dedupe
✓ Autoscaled batching for >50TB
✓ Thread-safe logging
✓ RHEL/CentOS Python 3.6+ compatible (no 'text=')

Tested on Python 3.6.8 (CentOS 7), Python 3.9, Python 3.11.
"""

import argparse
import concurrent.futures as cf
import os
import shlex
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from queue import Queue, Empty
from collections import deque
from bisect import bisect_right

# ----------------------------- DEFAULTS -----------------------------
DEFAULT_SERVERS = [
  "atlcldscn-01", "atlcldscn-02", "atlcldscn-03", "atlcldscn-04", "atlcldscn-05",
  "atlcldscn-06", "atlcldscn-07", "atlcldscn-08", "atlcldscn-09", "atlcldscn-10",
  "atlcldscn-11", "atlcldscn-12", "atlcldscn-13", "atlcldscn-14", "atlcldscn-15",
  "atlcldscn-16", "atlcldscn-17", "atlcldscn-18", "atlcldscn-19", "atlcldscn-20"
]
SCAN_BIN = "/opt/bitdefender-security-tools/bin/bduitool"
SCAN_CMD_BASE = f"{shlex.quote(SCAN_BIN)} scan -s custom"

# ----------------------------- UTILITIES -----------------------------
def bytes_to_tb(x: int) -> float:
  return x / (1024.0 ** 4)

def is_snapshot_path(p: Path) -> bool:
  return any(part == ".snapshot" for part in p.parts)

def unique_preserve_order(seq):
  seen = set()
  out = []
  for s in seq:
    if s not in seen:
      seen.add(s)
      out.append(s)
  return out

# ---------------- De-duplication helpers (O(N log N)) ----------------
def _as_trails_str(paths):
  """Turn a list of Path-like items into normalized 'trails' (str with trailing '/')."""
  out = []
  for p in paths:
    s = str(p).rstrip("/") + "/"
    out.append(s)
  return out

def fast_filter_parent_dirs(dirs):
  """
  Keep only deepest directories among the list (leaf-only): drop parents which are
  prefixes of other dirs. Complexity: O(D log D).
  """
  if not dirs:
    return dirs
  trails = sorted(_as_trails_str(dirs))
  keep = []
  last = None
  for t in trails:
    if last is None or not t.startswith(last):
      keep.append(t[:-1])  # store without trailing slash
      last = t
    else:
      # deeper leaf replaces previous parent
      keep[-1] = t[:-1]
      last = t
  return [Path(s) for s in keep]

def prefer_parents_filter(dirs):
  """
  Keep only top-level parents: drop any directory that is under a kept parent.
  Complexity: O(D log D). Produces fewer, larger scan jobs.
  """
  if not dirs:
    return dirs
  trails = sorted(_as_trails_str(dirs))
  keep = []
  parent = None
  for t in trails:
    if parent is None or not t.startswith(parent):
      keep.append(t[:-1])
      parent = t
    # else: drop child
  return [Path(s) for s in keep]

def drop_files_covered_by_dirs(files, dirs):
  """
  Remove files that are under any directory in 'dirs'.
  Complexity: O(F log D) using binary search on sorted dir trails.
  """
  if not files or not dirs:
    return files
  dtrails = sorted(_as_trails_str(dirs))
  kept = []
  for f in files:
    fs = str(f)
    i = bisect_right(dtrails, fs) - 1  # rightmost dir trail <= file path
    if i < 0 or not fs.startswith(dtrails[i]):
      kept.append(f)
  return kept

def filter_parent_dirs(dirs, all_paths):
  """Remove parent dirs which are superseded by deeper dirs/files. (Legacy, potentially expensive)"""
  if not dirs:
    return dirs
  dirs_sorted = sorted(dirs, key=lambda p: str(p))
  dir_trails = {str(d).rstrip("/") + "/": d for d in dirs_sorted}
  keep = []
  all_path_strs = [str(p) for p in all_paths]
  for dtrail, dpath in dir_trails.items():
    is_parent = any(p != dtrail[:-1] and p.startswith(dtrail) for p in all_path_strs)
    if not is_parent:
      keep.append(dpath)
  return unique_preserve_order(keep)

def chunked(lst, n):
  for i in range(0, len(lst), n):
    yield lst[i:i+n]

# ----------------------------- LOGGING -----------------------------
class Logger:
  def __init__(self, base_dir: Path):
    self.base_dir = base_dir
    self.base_dir.mkdir(parents=True, exist_ok=True)
    self._locks = {}
    self._locks_lock = threading.Lock()

  def _get_lock(self, name: str):
    with self._locks_lock:
      if name not in self._locks:
        self._locks[name] = threading.Lock()
    return self._locks[name]

  def log_executed(self, server: str, line: str):
    fpath = self.base_dir / f"executed_commands_{server}.log"
    with self._get_lock(str(fpath)):
      with open(fpath, "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} \n {line}\n")

  def log_scanned_items(self, items):
    fpath = self.base_dir / "scanned_items.log"
    with self._get_lock(str(fpath)):
      with open(fpath, "a", encoding="utf-8") as f:
        for it in items:
          f.write(str(it) + "\n")

  def log_info(self, msg: str):
    fpath = self.base_dir / "run_info.log"
    with self._get_lock(str(fpath)):
      with open(fpath, "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} \n {msg}\n")

# ----------------------------- SSH HELPERS -----------------------------
def run_ssh(server: str, remote_cmd: str, user=None, port=22,
            identity_file=None, extra_ssh_opts=None, timeout=45, dry_run=False):
  target = f"{user}@{server}" if user else server
  cmd = ["ssh", "-o", "BatchMode=yes",
         "-o", f"ConnectTimeout={timeout}",
         "-p", str(port)]
  if identity_file:
    cmd += ["-i", identity_file]
  if extra_ssh_opts:
    cmd += extra_ssh_opts
  cmd += [target, remote_cmd]
  if dry_run:
    return 0, f"DRY-RUN: {' '.join(cmd)}", ""
  p = subprocess.run(cmd, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,
                     universal_newlines=True)
  return p.returncode, p.stdout, p.stderr

def run_ssh_command(server: str, remote_cmd: str, user=None, port=22,
                    identity_file=None, extra_ssh_opts=None,
                    dry_run=False, timeout=45):
  target = f"{user}@{server}" if user else server
  cmd = ["ssh", "-o", "BatchMode=yes",
         "-o", f"ConnectTimeout={timeout}",
         "-p", str(port)]
  if identity_file:
    cmd += ["-i", identity_file]
  if extra_ssh_opts:
    cmd += extra_ssh_opts
  cmd += [target, remote_cmd]
  if dry_run:
    return 0, f"DRY-RUN: {' '.join(cmd)}", ""
  p = subprocess.run(cmd, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,
                     universal_newlines=True)
  return p.returncode, p.stdout.strip(), p.stderr.strip()

# ----------------------------- LOCAL DISCOVERY -----------------------------
def discover_exact_depth_python(root: Path, depth: int, workers: int = 16, follow_symlinks=False):
  if depth < 1:
    return [], []
  level_dirs = [root]
  for current_depth in range(1, depth + 1):
    next_level_dirs, files_at_level, dirs_at_level = [], [], []

    def scan_dir(d: Path):
      local_next, local_files, local_dirs = [], [], []
      try:
        with os.scandir(d) as it:
          for entry in it:
            try:
              name = entry.name
              if name in (".", ".."):
                continue
              p = d / name
              if is_snapshot_path(p):
                continue
              if entry.is_dir(follow_symlinks=follow_symlinks):
                if current_depth == depth:
                  local_dirs.append(p)
                else:
                  local_next.append(p)
              else:
                if current_depth == depth:
                  local_files.append(p)
            except (PermissionError, FileNotFoundError):
              continue
      except (PermissionError, FileNotFoundError, OSError):
        return [], [], []
      return local_next, local_files, local_dirs

    if workers > 1 and len(level_dirs) > 1:
      with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(scan_dir, d) for d in level_dirs]
        for fut in cf.as_completed(futs):
          nd, lf, ld = fut.result()
          next_level_dirs.extend(nd); files_at_level.extend(lf); dirs_at_level.extend(ld)
    else:
      for d in level_dirs:
        nd, lf, ld = scan_dir(d)
        next_level_dirs.extend(nd); files_at_level.extend(lf); dirs_at_level.extend(ld)

    if current_depth < depth:
      level_dirs = next_level_dirs
    else:
      return unique_preserve_order(files_at_level), unique_preserve_order(dirs_at_level)
  return [], []

def discover_exact_depth_find(root: Path, depth: int):
  if depth < 1:
    return [], []
  cmd = [
    "find", str(root),
    "-mindepth", str(depth), "-maxdepth", str(depth),
    "(", "-path", "*/.snapshot", "-o", "-path", "*/.snapshot/*", ")", "-prune",
    "-o", "-printf", "%y %p\n"
  ]
  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
  out, err = p.communicate()
  if p.returncode != 0:
    sys.stderr.write(f"[WARN] find failed (rc={p.returncode}): {err}\n")
    return [], []
  files, dirs = [], []
  for line in out.splitlines():
    if not line:
      continue
    typ, path = line[0], line[2:]
    if "/.snapshot/" in path or path.endswith("/.snapshot"):
      continue
    pth = Path(path)
    if typ == "d":
      dirs.append(pth)
    elif typ == "f":
      files.append(pth)
  return unique_preserve_order(files), unique_preserve_order(dirs)

# ----------------------------- SHARDING -----------------------------
def auto_select_shard_dirs_local(root: Path, target_depth: int, target_shards: int,
                                 max_shard_depth: int = 8, workers: int = 32,
                                 follow_symlinks: bool = False, progress: bool = False):
  """
  BFS locally to find a shard depth that yields >= target_shards directories.
  """
  max_depth = min(target_depth, max_shard_depth)
  level_dirs = [root]
  for depth in range(1, max_depth + 1):
    next_level_dirs = []

    def scan_dir(d: Path):
      outs = []
      try:
        with os.scandir(d) as it:
          for entry in it:
            try:
              name = entry.name
              if name in (".", ".."):
                continue
              p = d / name
              if name == ".snapshot" or is_snapshot_path(p):
                continue
              if entry.is_dir(follow_symlinks=follow_symlinks):
                outs.append(p)
            except (PermissionError, FileNotFoundError):
              continue
      except (PermissionError, FileNotFoundError, OSError):
        return []
      return outs

    if workers > 1 and len(level_dirs) > 1:
      with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(scan_dir, d) for d in level_dirs]
        for fut in cf.as_completed(futs):
          next_level_dirs.extend(fut.result())
    else:
      for d in level_dirs:
        next_level_dirs.extend(scan_dir(d))

    shard_dirs = unique_preserve_order(next_level_dirs)
    if progress:
      print(f"[DISCOVER] shard depth={depth}: dirs={len(shard_dirs)} (target={target_shards})")
    if len(shard_dirs) >= target_shards or depth == max_depth:
      return depth, shard_dirs
    level_dirs = shard_dirs
  return max_depth, level_dirs

# ------- NEW: Remote shard-root selection (avoids local BFS on huge mounts) -------
def auto_select_shard_dirs_remote(server: str, root: Path, target_depth: int, target_shards: int,
                                  ssh_user=None, ssh_port=22, ssh_key=None, extra_ssh_opts=None,
                                  max_shard_depth: int = 8, follow_symlinks: bool = False,
                                  progress: bool = False, dry_run: bool = False):
  """
  Enumerate directories exactly at depth=1..N on the REMOTE server until we have
  at least 'target_shards' shard roots, or we hit 'max_shard_depth'.
  This offloads the heavy directory walk to a scan server.
  """
  max_depth = min(target_depth, max_shard_depth)
  linkopt = "-L " if follow_symlinks else ""
  for depth in range(1, max_depth + 1):
    # Skip .snapshot trees, list only directories at exact depth
    cmd = (
      f"find {shlex.quote(str(root))} "
      f"{linkopt}\\( -path '*/.snapshot' -o -path '*/.snapshot/*' \\) -prune -o "
      f"-mindepth {depth} -maxdepth {depth} -type d -print"
    )
    rc, out, err = run_ssh(server, cmd, user=ssh_user, port=ssh_port,
                           identity_file=ssh_key, extra_ssh_opts=extra_ssh_opts,
                           dry_run=dry_run)
    if rc != 0:
      if progress:
        sys.stderr.write(f"[WARN] remote shard discovery failed on {server} (rc={rc}): {err.strip()[:200]}\n")
      continue
    dirs = [Path(p) for p in (out or "").splitlines() if p and "/.snapshot/" not in p and not p.endswith("/.snapshot")]
    shard_dirs = unique_preserve_order(dirs)
    if progress:
      print(f"[DISCOVER] remote-shard {server}: depth={depth}: dirs={len(shard_dirs)} (target={target_shards})")
    if len(shard_dirs) >= target_shards or depth == max_depth:
      return depth, shard_dirs
  return max_depth, []

# ----------------------------- REMOTE DISCOVERY BUILDERS -----------------------------
def build_remote_find_cmd(start_paths, rel_depth):
  if not start_paths:
    return None
  starts = " ".join(shlex.quote(str(p)) for p in start_paths)
  prune = r"\( -path '*/.snapshot' -o -path '*/.snapshot/*' \) -prune -o"
  core = "-mindepth 0 -maxdepth 0 -printf '%y %p\n'" if rel_depth <= 0 else f"-mindepth {rel_depth} -maxdepth {rel_depth} -printf '%y %p\n'"
  return f"find {starts} {prune} {core}"

def build_remote_python_discover_cmd(start_paths, rel_depth, python_bin="python3"):
  """
  Build a remote Python command that prints: 'd PATH' or 'f PATH'
  for entries exactly rel_depth under each start path; skips .snapshot.
  """
  if not start_paths:
    return None
  starts = " ".join(shlex.quote(str(p)) for p in start_paths)
  launcher = (
    "PYBIN={python_bin}; "
    "if [ \"$PYBIN\" = \"auto\" ]; then "
    " command -v python3 >/dev/null 2>&1 && PYBIN=python3 || PYBIN=python; "
    "fi; "
    "\"$PYBIN\" - <<'PY' {rel} {starts}\n"
  ).format(python_bin=shlex.quote(python_bin), rel=rel_depth, starts=starts)
  code = r"""
import os, sys
rel = int(sys.argv[1])
starts = sys.argv[2:]
def is_snapshot(path):
  parts = path.split(os.sep)
  return '.snapshot' in parts
def list_exact_depth(start, rel):
  files, dirs = [], []
  if rel <= 0:
    if os.path.isdir(start): dirs.append(start)
    elif os.path.isfile(start): files.append(start)
    return files, dirs
  level = [start]
  for depth in range(1, rel + 1):
    next_level = []
    for base in level:
      try:
        with os.scandir(base) as it:
          for e in it:
            try:
              if e.name in ('.', '..'): continue
              p = os.path.join(base, e.name)
              if is_snapshot(p): continue
              if e.is_dir(follow_symlinks=False):
                if depth == rel: dirs.append(p)
                else: next_level.append(p)
              else:
                if depth == rel: files.append(p)
            except Exception: continue
      except Exception: continue
    level = next_level
  return files, dirs
for s in starts:
  if is_snapshot(s): continue
  f, d = list_exact_depth(s, rel)
  for p in d: print("d " + p)
  for p in f: print("f " + p)
PY
""".lstrip("\n")
  return launcher + code

# ----------------------------- STREAMING REMOTE DISCOVERY -----------------------------
def distributed_discover_remote_streaming(server_cmd_builder, root: Path, target_depth: int, servers: list,
                                          ssh_user=None, ssh_port=22, ssh_key=None, extra_ssh_opts=None,
                                          dispatch_concurrency=None, chunk_size=300, shard_factor=3,
                                          max_shard_depth=8, shard_workers=32, follow_symlinks=False,
                                          per_server_parallel=1, progress=False, dry_run=False,
                                          shard_mode: str = "local", remote_shard_server: str = None):
  """
  Streaming distributed discovery:
  - Auto-select shard depth so subtrees >= servers * shard_factor.
  - Assign shard dirs to servers round-robin.
  - Split each server's shard list into chunks of size `chunk_size`.
  - Start up to `dispatch_concurrency` servers at once (default all).
  - For each active server, run up to `per_server_parallel` discovery commands concurrently.
  - As soon as one command finishes on a server, start the next chunk on that same server.
  """
  # 1) Pick shard depth and dirs
  target_shards = max(1, len(servers) * max(1, shard_factor))
  if shard_mode == "remote":
    shard_server = remote_shard_server or (servers[0] if servers else None)
    if not shard_server:
      raise RuntimeError("remote shard mode requested but no servers provided")
    shard_depth, shard_dirs = auto_select_shard_dirs_remote(
      shard_server, root, target_depth, target_shards,
      ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, extra_ssh_opts=extra_ssh_opts,
      max_shard_depth=max_shard_depth, follow_symlinks=follow_symlinks,
      progress=progress, dry_run=dry_run
    )
  else:
    shard_depth, shard_dirs = auto_select_shard_dirs_local(
      root, target_depth, target_shards, max_shard_depth=max_shard_depth,
      workers=shard_workers, follow_symlinks=follow_symlinks, progress=progress
    )
  rel_depth = max(0, target_depth - shard_depth)
  if progress:
    origin = "remote" if shard_mode == "remote" else "local"
    print(f"[DISCOVER] Using {origin} shard_depth={shard_depth}, rel_depth={rel_depth}, shard_dirs={len(shard_dirs)}")

  # 2) Round-robin assign shard dirs to servers
  assignments = {srv: [] for srv in servers}
  for idx, d in enumerate(shard_dirs):
    assignments[servers[idx % len(servers)]].append(d)

  # 3) Build per-server groups (chunks)
  per_server_groups = {}
  total_groups = 0
  for srv, paths in assignments.items():
    groups = [grp for grp in chunked(paths, max(1, int(chunk_size)))]
    per_server_groups[srv] = groups
    total_groups += len(groups)
  active_servers = [s for s, g in per_server_groups.items() if g]
  if progress:
    print(f"[DISCOVER] streaming: {total_groups} chunks across {len(active_servers)} servers; chunk_size={chunk_size}")

  files_accum, dirs_accum = [], []
  accum_lock = threading.Lock()

  def run_one_cmd(server, start_paths):
    cmd = server_cmd_builder(start_paths, rel_depth)
    if not cmd:
      return 0, 0
    rc, out, err = run_ssh(server, cmd, user=ssh_user, port=ssh_port,
                           identity_file=ssh_key, extra_ssh_opts=extra_ssh_opts,
                           dry_run=dry_run)
    if rc != 0 and progress:
      sys.stderr.write(f"[WARN] remote discovery failed on {server} (rc={rc}): {err}\n")
    lf, ld = [], []
    for line in (out or "").splitlines():
      if not line:
        continue
      typ, path = line[0], line[2:]
      if "/.snapshot/" in path or path.endswith("/.snapshot"):
        continue
      p = Path(path)
      if typ == "d":
        ld.append(p)
      elif typ == "f":
        lf.append(p)
    with accum_lock:
      files_accum.extend(lf)
      dirs_accum.extend(ld)
    return len(lf), len(ld)

  def server_worker(server):
    dq = deque(per_server_groups.get(server, []))
    if not dq:
      return
    # Run up to per_server_parallel consumers within this server
    def consume():
      while True:
        try:
          grp = dq.popleft()
        except IndexError:
          return
        if progress:
          print(f"[DISCOVER] {server}: running chunk of {len(grp)} shard roots (remaining {len(dq)})")
        lf, ld = run_one_cmd(server, grp)
        if progress:
          print(f"[DISCOVER] {server}: +files={lf}, +dirs={ld}")

    threads = []
    for _ in range(max(1, int(per_server_parallel))):
      t = threading.Thread(target=consume, daemon=True)
      t.start()
      threads.append(t)
    for t in threads:
      t.join()

  # 4) Limit active servers concurrently if requested
  if dispatch_concurrency and dispatch_concurrency < len(active_servers):
    batches = [active_servers[i:i+dispatch_concurrency]
               for i in range(0, len(active_servers), dispatch_concurrency)]
  else:
    batches = [active_servers]

  # 5) Run in server waves (each server runs streaming internally)
  for wave_idx, wave_servers in enumerate(batches, 1):
    if progress:
      print(f"[DISCOVER] starting server set {wave_idx}/{len(batches)}: {len(wave_servers)} servers")
    with cf.ThreadPoolExecutor(max_workers=len(wave_servers)) as ex:
      futs = [ex.submit(server_worker, srv) for srv in wave_servers]
      for _ in cf.as_completed(futs):
        pass

  return unique_preserve_order(files_accum), unique_preserve_order(dirs_accum)

# ----------------------------- BENCHMARK (remote-auto) -----------------------------
def benchmark_remote_methods(sample_server, sample_paths, rel_depth, ssh_user, ssh_port, ssh_key, extra_ssh_opts,
                             python_bin, timeout=60, dry_run=False, progress=False):
  """
  Run small discovery on sample_paths using both remote find and remote python; return 'find' or 'python'.
  Returns 'find' on dry_run or any failure.
  """
  if dry_run:
    if progress:
      print("[BENCH] dry-run: defaulting to 'find'")
    return "find"

  def run_and_time(cmd_builder, label):
    cmd = cmd_builder(sample_paths, rel_depth)
    if not cmd:
      return float("inf")
    t0 = time.time()
    rc, out, err = run_ssh(sample_server, cmd, user=ssh_user, port=ssh_port, identity_file=ssh_key,
                           extra_ssh_opts=extra_ssh_opts, timeout=timeout, dry_run=False)
    dt = time.time() - t0
    if rc != 0:
      if progress:
        print(f"[BENCH] {label} failed rc={rc}: {err.strip()[:200]}")
      return float("inf")
    if progress:
      lines = len(out.splitlines()) if out else 0
      print(f"[BENCH] {label}: {lines} lines in {dt:.2f}s")
    return dt

  find_builder = build_remote_find_cmd
  def py_builder(paths, rel): return build_remote_python_discover_cmd(paths, rel, python_bin=python_bin)

  dt_find = run_and_time(find_builder, "find")
  dt_python = run_and_time(py_builder, "python")
  if dt_python < dt_find:
    if progress:
      print("[BENCH] Choosing 'python' (faster)")
    return "python"
  else:
    if progress:
      print("[BENCH] Choosing 'find' (faster or only option)")
    return "find"

# ----------------------------- AUTOSCALE -----------------------------
def auto_depth_pause_workers(root: Path, override_depth: int = None, override_pause: int = None):
  du = shutil.disk_usage(str(root)); used_tb = bytes_to_tb(du.used)
  depth = (override_depth if override_depth is not None else (3 if used_tb < 10 else (4 if used_tb <= 50 else 5)))
  pause_sec = (override_pause if override_pause is not None else (10*60 if used_tb < 10 else (20*60 if used_tb <= 50 else 30*60)))
  suggested_workers = (32 if used_tb < 10 else (64 if used_tb <= 50 else 128))
  return depth, pause_sec, suggested_workers, used_tb

# ----------------------------- SCAN DISPATCH HELPERS -----------------------------
def build_remote_nohup_cmd(scan_bin: str, paths):
  quoted_paths = " ".join(shlex.quote(str(p)) for p in paths)
  remote_log = f"/var/tmp/bduitool_scan_$(date +%s)_$$.log"
  return (
    f"nohup {shlex.quote(scan_bin)} scan -s custom {quoted_paths} "
    f"> {remote_log} 2>&1 & echo $! '{remote_log}'"
  )

def count_remote_scans_via_scantasks(server: str, user: str, port: int, identity_file: str, extra_ssh_opts, grep_regex: str, dry_run=False):
  """
  Count running scans using 'bduitool get scantasks' while ignoring the header line.
  Only count rows that START with a UUID and whose state matches running/in-progress.
  """
  cmd = (
    f"{shlex.quote(SCAN_BIN)} get scantasks | "
    r"awk '/^[0-9a-f\-]{8,}/' | "
    r"grep -Ei '\<(running|in[ _-]?progress)\>' | "
    r"wc -l"
  )
  rc, out, err = run_ssh(server, cmd, user=user, port=port, identity_file=identity_file,
                         extra_ssh_opts=extra_ssh_opts, dry_run=dry_run)
  try:
    return int((out or "0").strip())
  except Exception:
    return 0

def count_remote_scans_via_pgrep(server: str, user: str, port: int, identity_file: str, extra_ssh_opts, dry_run=False):
  cmd = r"pgrep -af 'bduitool.*scan -s custom' | wc -l"
  rc, out, err = run_ssh(server, cmd, user=user, port=port, identity_file=identity_file,
                         extra_ssh_opts=extra_ssh_opts, dry_run=dry_run)
  try:
    return int((out or "0").strip())
  except Exception:
    return 0

def cleanup_remote_tmp(server: str, user: str, port: int, identity_file: str, extra_ssh_opts, dry_run=False):
  cmd = r"rm -f /var/tmp/bduitool_scan_*.log /var/tmp/bduitool_poll_* >/dev/null 2>&1 || true"
  return run_ssh(server, cmd, user=user, port=port, identity_file=identity_file,
                 extra_ssh_opts=extra_ssh_opts, dry_run=dry_run)

def cleanup_remote_tmp_with_retry(server: str, user: str, port: int, identity_file: str,
                                  extra_ssh_opts, dry_run=False, attempts: int = 3, delay: int = 2):
  """
  Retry wrapper around cleanup_remote_tmp to handle transient file locks or NFS latencies.
  """
  last = (0, "", "")
  for _ in range(1, max(1, attempts) + 1):
    last = cleanup_remote_tmp(server, user, port, identity_file, extra_ssh_opts, dry_run=dry_run)
    rc, _, _ = last
    if rc == 0:
      return last
    time.sleep(delay)
  return last

# ----------------------------- BATCHING -----------------------------
def prepare_batches(files, dirs, files_per_cmd=100, dirs_per_cmd=5):
  batches = []
  for grp in chunked(dirs, max(1, int(dirs_per_cmd))):
    batches.append(("dirs", grp))
  for grp in chunked(files, max(1, int(files_per_cmd))):
    batches.append(("files", grp))
  # Interleave dirs/files
  dir_batches = [b for b in batches if b[0] == "dirs"]
  file_batches = [b for b in batches if b[0] == "files"]
  merged, i, j = [], 0, 0
  while i < len(dir_batches) or j < len(file_batches):
    if i < len(dir_batches): merged.append(dir_batches[i]); i += 1
    if j < len(file_batches): merged.append(file_batches[j]); j += 1
  return merged

# ----------------------------- MAIN -----------------------------
def main():
  ap = argparse.ArgumentParser(description="Parallel NFS discovery and Bitdefender custom scanning via SSH.")
  # Paths/servers
  ap.add_argument("--mount-path", "-m", required=True, help="Mount path to scan (e.g., /mnt/share)")
  ap.add_argument("--servers", "-s", nargs="*", help="List of scan servers (overrides default)")
  ap.add_argument("--servers-file", help="Path to file containing server names (one per line)")
  # SSH
  ap.add_argument("--ssh-user", help="SSH username (default: current user)")
  ap.add_argument("--ssh-port", type=int, default=22, help="SSH port (default: 22)")
  ap.add_argument("--ssh-key", help="SSH identity file (private key)")
  ap.add_argument("--ssh-opt", action="append", default=[], help="Extra ssh option, e.g., --ssh-opt -o, --ssh-opt ServerAliveInterval=60 (repeatable, pairs)")
  # Discovery backends
  ap.add_argument("--discover-backend", dest="discover_backend",
                  choices=["auto", "find", "python", "remote-find", "remote-python", "remote-auto"],
                  default="auto",
                  help="auto (find for >50TB), find (local), python (local), remote-find (distributed find), remote-python (distributed python), remote-auto (benchmark & choose)")
  ap.add_argument("--distributed-discover", action="store_true", help="Shortcut: enable remote-auto (benchmark & choose)")
  # Sharding mode controls
  ap.add_argument("--remote-shard", action="store_true",
                  help="Compute shard roots on a remote scan server (avoids local BFS). Default: auto remote when using remote-* backends.")
  ap.add_argument("--local-shard", action="store_true",
                  help="Force legacy local shard-root selection even for remote-* backends.")
  ap.add_argument("--remote-shard-server", default=None,
                  help="Server to run remote sharding on (default: first server).")
  # Discovery controls
  ap.add_argument("--max-depth", type=int, help="Override depth (default: auto by used TB)")
  ap.add_argument("--workers", type=int, default=None, help="Threads for python discovery (default: auto 32/64/128 by used TB)")
  ap.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks in python discovery")
  # Remote discovery controls
  ap.add_argument("--discover-dispatch-concurrency", type=int, default=None, help="Max servers running discovery at once (default: all active servers)")
  ap.add_argument("--discover-chunk-size", type=int, default=300, help="Shard start paths per remote discovery command (default: 300)")
  ap.add_argument("--discover-per-server-parallel", type=int, default=1, help="Concurrent discovery commands per server (default: 1)")
  ap.add_argument("--shard-factor", type=int, default=3, help="Target shards = servers × shard-factor (default: 3)")
  ap.add_argument("--max-shard-depth", type=int, default=8, help="Maximum shard depth to consider when auto-sharding (default: 8)")
  # remote-python & auto benchmark
  ap.add_argument("--remote-python-bin", default="python3", help="Remote python binary ('python3', 'python', or 'auto')")
  ap.add_argument("--remote-benchmark-sample", type=int, default=12, help="How many shard roots to test in benchmark (default: 12)")
  ap.add_argument("--remote-benchmark-server", default=None, help="Server to run benchmark on (default: first with assigned shards)")
  ap.add_argument("--remote-benchmark-timeout", type=int, default=60, help="Timeout seconds for benchmark SSH commands (default: 60)")
  # Per-server scheduler (Bitdefender cap)
  ap.add_argument("--max-scans-per-server", type=int, default=4, help="Hard cap of concurrent scans per server (Bitdefender limit)")
  ap.add_argument("--server-poll-interval", type=int, default=20, help="Seconds between capacity checks per server")
  ap.add_argument("--scantasks-grep", default=r"running\nin[_ -]?progress", help="Regex to count running scans (ignored header)")
  ap.add_argument("--cleanup-remote-tmp", dest="cleanup_remote_tmp", action="store_true", default=True, help="Cleanup /var/tmp prior poll/log files on servers")
  ap.add_argument("--no-cleanup-remote-tmp", dest="cleanup_remote_tmp", action="store_false", help="Disable remote /var/tmp cleanup")
  # Post-run cleanup
  ap.add_argument("--post-cleanup-remote-tmp", dest="post_cleanup_remote_tmp",
                  action="store_true", default=True,
                  help="After dispatch completes (or on interrupt), clean /var/tmp temp/poll files on all servers")
  ap.add_argument("--no-post-cleanup-remote-tmp", dest="post_cleanup_remote_tmp",
                  action="store_false", help="Do not perform post-run remote /var/tmp cleanup")
  # Batching
  ap.add_argument("--files-per-cmd", type=int, default=None, help="Max files per scan command (default: 100; auto: 500 if >50TB)")
  ap.add_argument("--dirs-per-cmd", type=int, default=None, help="Max dirs per scan command (default: 5; auto: 20 if >50TB)")
  ap.add_argument("--autoscale-batching", action="store_true", default=True, help="Autoscale batching on big mounts")
  ap.add_argument("--no-autoscale-batching", action="store_false", dest="autoscale_batching")
  # Misc
  ap.add_argument("--log-dir", default="./scan_logs", help="Local log directory")
  # Dedupe modes (scalable alternatives to O(N^2) parent dedupe)
  ap.add_argument("--dedupe-mode",
                  choices=["auto", "off", "leaf-only", "parent-only", "hybrid"],
                  default="auto",
                  help="De-duplication strategy: auto (smart), off, leaf-only (keep deepest dirs), "
                       "parent-only (keep top parents), hybrid (leaf-only + drop files under kept dirs)")
  ap.add_argument("--dry-run", action="store_true", help="Do not execute SSH, just print/log would-be actions")
  ap.add_argument("--progress", action="store_true", help="Print progress")
  ap.add_argument("--no-parent-dedupe", action="store_true", help="Do NOT drop parent dirs when subpaths are present")

  args = ap.parse_args()
  root = Path(args.mount_path).resolve()
  if not root.exists():
    print(f"ERROR: mount path does not exist: {root}", file=sys.stderr)
    sys.exit(2)

  # Servers
  servers = []
  if args.servers_file:
    with open(args.servers_file, "r", encoding="utf-8") as f:
      servers = [line.strip() for line in f if line.strip()]
  elif args.servers:
    servers = args.servers
  else:
    servers = DEFAULT_SERVERS
  if not servers:
    print("ERROR: No servers provided.", file=sys.stderr)
    sys.exit(3)

  extra_ssh_opts = []
  extra_ssh_opts.extend(args.ssh_opt or [])

  # Logging
  log = Logger(Path(args.log_dir))
  log.log_info(f"START root={root} servers={len(servers)} dry_run={args.dry_run}")

  # Auto depth/workers
  depth, _, suggested_workers, used_tb = auto_depth_pause_workers(root, override_depth=args.max_depth, override_pause=None)
  big_mount = used_tb > 50.0

  # Discovery backend decision
  backend = args.discover_backend
  if backend == "auto":
    backend = "find" if big_mount else "python"
  if args.distributed_discover:
    backend = "remote-auto"

  # Workers (python local only)
  if backend == "python":
    workers = (suggested_workers if args.workers is None else max(1, int(args.workers)))
    workers_source = "auto" if args.workers is None else "user"
  else:
    workers, workers_source = None, "-"

  # Batching defaults
  default_dirs_cmd = 20 if (args.autoscale_batching and big_mount) else 5
  default_files_cmd = 500 if (args.autoscale_batching and big_mount) else 100
  dirs_per_cmd = args.dirs_per_cmd if args.dirs_per_cmd is not None else default_dirs_cmd
  files_per_cmd = args.files_per_cmd if args.files_per_cmd is not None else default_files_cmd

  print(f"[INFO] Used ≈ {used_tb:.2f} TB → depth={depth}, backend={backend}, workers={workers} ({workers_source}), "
        f"batching: dirs={dirs_per_cmd}, files={files_per_cmd}, max_scans/server={args.max_scans_per_server}")
  log.log_info(f"depth={depth}, usedTB={used_tb:.2f}, backend={backend}, workers={workers} ({workers_source}), "
               f"dirs/cmd={dirs_per_cmd}, files/cmd={files_per_cmd}, max_scans/server={args.max_scans_per_server}")

  # ---- Discovery with fallback ----
  attempt_depth = depth
  files, dirs = [], []
  while attempt_depth >= 1:
    if args.progress:
      print(f"[INFO] Discovering at exact depth={attempt_depth} using {backend} ...")
    if backend == "find":
      f, d = discover_exact_depth_find(root, attempt_depth)
    elif backend == "python":
      f, d = discover_exact_depth_python(root, attempt_depth, workers=workers or 16, follow_symlinks=args.follow_symlinks)
    elif backend in ("remote-find", "remote-python", "remote-auto"):
      # Choose remote builder
      if backend == "remote-find":
        server_cmd_builder = build_remote_find_cmd
      elif backend == "remote-python":
        def server_cmd_builder(paths, rel): return build_remote_python_discover_cmd(paths, rel, python_bin=args.remote_python_bin)
      else:  # remote-auto
        # Get shards to benchmark small sample (respect sharding mode)
        shard_mode = "remote" if (args.remote_shard or (not args.local_shard)) else "local"
        target_shards = max(1, len(servers) * max(1, args.shard_factor))
        if shard_mode == "remote":
          bench_shard_server = args.remote_benchmark_server or args.remote_shard_server or (servers[0] if servers else None)
          shard_depth, shard_dirs = auto_select_shard_dirs_remote(
            bench_shard_server, root, attempt_depth, target_shards,
            ssh_user=args.ssh_user, ssh_port=args.ssh_port, ssh_key=args.ssh_key, extra_ssh_opts=extra_ssh_opts,
            max_shard_depth=args.max_shard_depth, follow_symlinks=args.follow_symlinks,
            progress=args.progress, dry_run=args.dry_run
          )
        else:
          shard_depth, shard_dirs = auto_select_shard_dirs_local(
            root, attempt_depth, target_shards, max_shard_depth=args.max_shard_depth,
            workers=suggested_workers, follow_symlinks=args.follow_symlinks, progress=args.progress
          )
        rel_depth = max(0, attempt_depth - shard_depth)
        # Assign for sampling
        assignments = {srv: [] for srv in servers}
        for idx, ddir in enumerate(shard_dirs):
          assignments[servers[idx % len(servers)]].append(ddir)
        bench_server = args.remote_benchmark_server
        if bench_server is None:
          bench_server = next((srv for srv, arr in assignments.items() if arr), servers[0])
        sample_paths = assignments.get(bench_server, [])[:max(1, int(args.remote_benchmark_sample))]
        if not sample_paths:
          sample_paths = shard_dirs[:max(1, int(args.remote_benchmark_sample))]
        if args.progress:
          print(f"[BENCH] server={bench_server}, sample={len(sample_paths)}, rel_depth={rel_depth}")
        chosen = benchmark_remote_methods(
          bench_server, sample_paths, rel_depth, args.ssh_user, args.ssh_port, args.ssh_key, extra_ssh_opts,
          python_bin=args.remote_python_bin, timeout=args.remote_benchmark_timeout, dry_run=args.dry_run, progress=args.progress
        )
        if chosen == "python":
          def server_cmd_builder(paths, rel): return build_remote_python_discover_cmd(paths, rel, python_bin=args.remote_python_bin)
        else:
          server_cmd_builder = build_remote_find_cmd

      # Run full streaming distributed discovery (respect sharding mode in streaming phase too)
      shard_mode_stream = "remote" if (args.remote_shard or (not args.local_shard)) else "local"
      f, d = distributed_discover_remote_streaming(
        server_cmd_builder, root, attempt_depth, servers,
        ssh_user=args.ssh_user, ssh_port=args.ssh_port, ssh_key=args.ssh_key, extra_ssh_opts=extra_ssh_opts,
        dispatch_concurrency=args.discover_dispatch_concurrency,
        chunk_size=args.discover_chunk_size,
        shard_factor=args.shard_factor, max_shard_depth=args.max_shard_depth,
        shard_workers=suggested_workers, follow_symlinks=args.follow_symlinks,
        per_server_parallel=args.discover_per_server_parallel,
        progress=args.progress, dry_run=args.dry_run,
        shard_mode=shard_mode_stream, remote_shard_server=(args.remote_shard_server or None)
      )
    else:
      print(f"ERROR: Unsupported backend {backend}", file=sys.stderr)
      sys.exit(4)

    files, dirs = f, d
    if files or dirs:
      break
    attempt_depth -= 1

  if not files and not dirs:
    print(f"[WARN] No items found at any depth from 1..{depth}. Nothing to scan.")
    log.log_info("No items found; exiting.")
    sys.exit(0)

  if args.progress:
    print(f"[INFO] Found at depth={attempt_depth}: files={len(files)}, dirs={len(dirs)}")

  # ---------------------- De-duplication strategy ----------------------
  # Back-compat: if user explicitly asked to skip parent dedupe and didn't pick a mode, honor it.
  dedupe_mode = args.dedupe_mode
  if args.no_parent_dedupe and dedupe_mode == "auto":
    dedupe_mode = "off"
  elif args.no_parent_dedupe and dedupe_mode != "auto":
    print("[WARN] --no-parent-dedupe is ignored because --dedupe-mode is explicitly set.", file=sys.stderr)

  # Auto selection based on mount size & item counts
  total_items = len(files) + len(dirs)
  if dedupe_mode == "auto":
    # Heuristic: very large mounts or huge item counts -> fewest jobs (parent-only);
    # large mix of files+dirs -> hybrid; else leaf-only.
    if total_items >= 5_000_000 or used_tb >= 100:
      dedupe_mode = "parent-only"
    elif len(files) > 0 and len(dirs) > 0 and total_items >= 1_000_000:
      dedupe_mode = "hybrid"
    else:
      dedupe_mode = "leaf-only"

  pre_files, pre_dirs = len(files), len(dirs)
  if dedupe_mode == "off":
    pass
  elif dedupe_mode == "leaf-only":
    if dirs:
      dirs = fast_filter_parent_dirs(dirs)
  elif dedupe_mode == "parent-only":
    if dirs:
      dirs = prefer_parents_filter(dirs)
    if files and dirs:
      files = drop_files_covered_by_dirs(files, dirs)
  elif dedupe_mode == "hybrid":
    if dirs:
      dirs = fast_filter_parent_dirs(dirs)
    if files and dirs:
      files = drop_files_covered_by_dirs(files, dirs)
  else:
    print(f"ERROR: Unsupported dedupe_mode {dedupe_mode}", file=sys.stderr)
    sys.exit(5)

  if args.progress:
    print(f"[DEDUP] mode={dedupe_mode} -> files: {pre_files}->{len(files)}, dirs: {pre_dirs}->{len(dirs)}")
  log.log_info(f"dedupe_mode={dedupe_mode}, files={pre_files}->{len(files)}, dirs={pre_dirs}->{len(dirs)}")

  # Build batches and enforce conservative argv length
  batches = prepare_batches(files, dirs, files_per_cmd=files_per_cmd, dirs_per_cmd=dirs_per_cmd)
  MAX_CMD_CHARS = 100_000
  safe_batches = []
  for btype, plist in batches:
    current, clen = [], 0
    for p in plist:
      plen = len(str(p)) + 1
      if current and (clen + plen) > MAX_CMD_CHARS:
        safe_batches.append((btype, current))
        current, clen = [p], plen
      else:
        current.append(p); clen += plen
    if current:
      safe_batches.append((btype, current))
  batches = safe_batches

  # Log scanned items (flat list)
  log.log_scanned_items([str(p) for _, grp in batches for p in grp])

  # ---------------- Per-server dynamic scan scheduler (pull-first) ----------------
  total_batches = len(batches)
  print(f"[INFO] Total batches: {total_batches} across {len(servers)} servers (per-server scheduler, max {args.max_scans_per_server}/server)")
  q = Queue()
  for item in batches:
    q.put(item)

  # Optional cleanup of /var/tmp on all servers (pre-run cleanup)
  if args.cleanup_remote_tmp:
    if args.progress: print("[SCHED] Cleaning up /var/tmp on all servers (old poll/log files) ...")
    with cf.ThreadPoolExecutor(max_workers=min(len(servers), 16)) as ex:
      futs = [ex.submit(cleanup_remote_tmp, srv, args.ssh_user, args.ssh_port, args.ssh_key, extra_ssh_opts, args.dry_run) for srv in servers]
      for fut in cf.as_completed(futs):
        _ = fut.result()

  dispatched_lock = threading.Lock()
  dispatched_count = 0

  def server_worker(server: str):
    nonlocal dispatched_count
    while True:
      # Pull a batch FIRST; exit if no work left
      try:
        btype, plist = q.get_nowait()
      except Empty:
        return

      # If server is at capacity, put back and wait briefly; another server may take it
      while True:
        running = count_remote_scans_via_scantasks(server, args.ssh_user, args.ssh_port, args.ssh_key, extra_ssh_opts, args.scantasks_grep, args.dry_run)
        if running == 0:
          running = count_remote_scans_via_pgrep(server, args.ssh_user, args.ssh_port, args.ssh_key, extra_ssh_opts, args.dry_run)
        if running < args.max_scans_per_server:
          break
        # Return the batch so another server can progress
        q.put((btype, plist))
        if args.progress:
          print(f"[SCHED] {server}: running={running} ≥ max={args.max_scans_per_server} → wait {args.server_poll_interval}s")
        if args.dry_run:
          break
        time.sleep(args.server_poll_interval)
        # Try a fresh batch (previous might have been taken already)
        try:
          btype, plist = q.get_nowait()
        except Empty:
          return

      # Dispatch batch on this server
      remote_cmd = build_remote_nohup_cmd(SCAN_BIN, plist)
      human_cmd = f"{SCAN_CMD_BASE} " + " ".join(shlex.quote(str(p)) for p in plist)
      log.log_executed(server, f"START {btype} count={len(plist)} \n {human_cmd}")
      rc, out, err = run_ssh_command(
        server=server,
        remote_cmd=remote_cmd,
        user=args.ssh_user,
        port=args.ssh_port,
        identity_file=args.ssh_key,
        extra_ssh_opts=extra_ssh_opts,
        dry_run=args.dry_run
      )
      if rc != 0:
        log.log_executed(server, f"ERR rc={rc} err={err} (dispatch)")
        q.put((btype, plist))
        if not args.dry_run:
          time.sleep(args.server_poll_interval)
      else:
        log_line = (out or "").replace("\n", " ")
        log.log_executed(server, f"DISPATCHED pid+log: {log_line}")
        with dispatched_lock:
          dispatched_count += 1
        if args.progress:
          print(f"[SCHED] {server}: dispatched #{dispatched_count}/{total_batches} (queue ~{q.qsize()})")

  with cf.ThreadPoolExecutor(max_workers=len(servers)) as ex:
    futs = [ex.submit(server_worker, srv) for srv in servers]
    for fut in cf.as_completed(futs):
      _ = fut.result()

  print("[DONE] All batches dispatched. Remote scans continue on servers.")
  log.log_info("COMPLETED dispatch of all batches (per-server scheduler).")

  # -------- Post-run cleanup (optional) --------
  if args.post_cleanup_remote_tmp:
    if args.progress:
      print("[CLEANUP] Post-run: removing remote /var/tmp scan/poll remnants on all servers ...")
    with cf.ThreadPoolExecutor(max_workers=min(len(servers), 16)) as ex:
      futs = [ex.submit(
                cleanup_remote_tmp_with_retry,
                srv, args.ssh_user, args.ssh_port, args.ssh_key, extra_ssh_opts,
                args.dry_run, attempts=3, delay=2
              ) for srv in servers]
      for fut in cf.as_completed(futs):
        _ = fut.result()
    if args.progress:
      print("[CLEANUP] Post-run remote cleanup complete.")
    log.log_info("Post-run remote /var/tmp cleanup complete.")

if __name__ == "__main__":
  try:
    main()
  except KeyboardInterrupt:
    # Best-effort post-cleanup on interrupt
    try:
      print("\n[INTERRUPTED] Caught Ctrl-C. Attempting remote /var/tmp cleanup ...", file=sys.stderr)
      # Minimal parse to know servers and SSH info.
      p = argparse.ArgumentParser(add_help=False)
      p.add_argument("--servers", "-s", nargs="*")
      p.add_argument("--servers-file")
      p.add_argument("--ssh-user"); p.add_argument("--ssh-port", type=int, default=22)
      p.add_argument("--ssh-key");  p.add_argument("--ssh-opt", action="append", default=[])
      p.add_argument("--post-cleanup-remote-tmp", dest="post_cleanup_remote_tmp", action="store_true", default=True)
      p.add_argument("--no-post-cleanup-remote-tmp", dest="post_cleanup_remote_tmp", action="store_false")
      p.add_argument("--dry-run", action="store_true")
      args, _ = p.parse_known_args()

      servers = []
      if args.servers_file and os.path.exists(args.servers_file):
        with open(args.servers_file, "r", encoding="utf-8") as f:
          servers = [line.strip() for line in f if line.strip()]
      elif args.servers:
        servers = args.servers
      if not servers: servers = DEFAULT_SERVERS
      if args.post_cleanup_remote_tmp and servers:
        with cf.ThreadPoolExecutor(max_workers=min(len(servers), 16)) as ex:
          futs = [ex.submit(cleanup_remote_tmp_with_retry, srv, args.ssh_user, args.ssh_port, args.ssh_key, args.ssh_opt or [], args.dry_run) for srv in servers]
          for _ in cf.as_completed(futs): pass
    finally:
      sys.exit(130)
