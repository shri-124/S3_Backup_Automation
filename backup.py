#!/usr/bin/env python3
import argparse, hashlib, json, os, sys, time
from datetime import datetime
from pathlib import Path
import boto3
from botocore.config import Config
from typing import Optional

CHUNK = 1024 * 1024  # 1 MiB

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b: break
            h.update(b)
    return h.hexdigest()

def sha256_stream(body) -> str:
    h = hashlib.sha256()
    while True:
        b = body.read(CHUNK)
        if not b: break
        h.update(b)
    return h.hexdigest()

def load_manifest(manifest_path: Path) -> dict:
    if manifest_path.exists():
        return json.loads(manifest_path.read_text())
    return {"files": {}, "created_at": datetime.utcnow().isoformat() + "Z"}

def save_manifest(manifest_path: Path, data: dict):
    data["updated_at"] = datetime.utcnow().isoformat() + "Z"
    manifest_path.write_text(json.dumps(data, indent=2))

def s3_client(endpoint_url: Optional[str]):
    sess = boto3.session.Session()
    return sess.client(
        "s3",
        endpoint_url=endpoint_url or None,
        config=Config(retries={"max_attempts": 5, "mode": "standard"}),
    )

def put_object(client, bucket, key, file_path: Path, sha256: str, storage_class=None):
    extra = {"Metadata": {"sha256": sha256}}
    if storage_class: extra["StorageClass"] = storage_class

    with file_path.open("rb") as f:
        client.put_object(Bucket=bucket, Key=key, Body=f, **extra)

def get_object_head(client, bucket, key):
    return client.head_object(Bucket=bucket, Key=key)

def get_object(client, bucket, key):
    return client.get_object(Bucket=bucket, Key=key)

def list_local_files(root: Path):
    for p in root.rglob("*"):
        if p.is_file():
            yield p

def backup(args):
    root = Path(args.source).resolve()
    if not root.exists():
        print(f"Source not found: {root}", file=sys.stderr)
        sys.exit(1)

    manifest_path = Path(args.manifest)
    manifest = load_manifest(manifest_path)

    client = s3_client(args.endpoint)

    uploaded, skipped, verified = 0, 0, 0
    for f in list_local_files(root):
        rel = str(f.relative_to(root)).replace("\\", "/")
        key = f"{args.prefix.rstrip('/')}/{rel}" if args.prefix else rel

        sha_local = sha256_file(f)
        prev = manifest["files"].get(rel)

        if prev and prev.get("sha256") == sha_local and not args.force:
            print(f"[skip] {rel} (unchanged)")
            skipped += 1
            continue

        print(f"[upload] {rel}")
        if not args.dry_run:
            put_object(client, args.bucket, key, f, sha_local, args.storage_class)

            # Record latest version id (if versioning enabled)
            try:
                head = get_object_head(client, args.bucket, key)
                version_id = head.get("VersionId")
                meta_sha = head.get("Metadata", {}).get("sha256")
            except Exception:
                version_id, meta_sha = None, None

            # Integrity verify
            ok = True
            if args.verify:
                # Strong verify: re-download and hash (good for small/medium files)
                obj = get_object(client, args.bucket, key)
                sha_remote = sha256_stream(obj["Body"])
                obj["Body"].close()
                ok = (sha_remote == sha_local)
                if ok: verified += 1
                print(f"  - verify: {'OK' if ok else 'MISMATCH'}")
            elif meta_sha:
                ok = (meta_sha == sha_local)
                if ok: verified += 1
                print(f"  - metadata check: {'OK' if ok else 'MISMATCH'}")

            manifest["files"][rel] = {
                "key": key,
                "sha256": sha_local,
                "size": f.stat().st_size,
                "mtime": int(f.stat().st_mtime),
                "version_id": version_id,
                "verified": ok,
                "ts": int(time.time()),
            }
            uploaded += 1

    if not args.dry_run:
        save_manifest(manifest_path, manifest)
        # also upload a copy of the manifest to the bucket with timestamp
        try:
            stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            remote_key = f"{args.prefix.rstrip('/')}/manifest_{stamp}.json" if args.prefix else f"manifest_{stamp}.json"
            s = json.dumps(manifest, indent=2).encode()
            s3_client(args.endpoint).put_object(
                Bucket=args.bucket, Key=remote_key, Body=s, Metadata={"type": "manifest"}
            )
        except Exception as e:
            print(f"Warn: failed to upload manifest copy: {e}", file=sys.stderr)

    print(f"\nDone. uploaded={uploaded} skipped={skipped} verified={verified}")

def restore(args):
    target = Path(args.restore_target).resolve()
    target.mkdir(parents=True, exist_ok=True)
    client = s3_client(args.endpoint)

    # Pull latest manifest (local or from bucket)
    manifest = None
    if Path(args.manifest).exists():
        manifest = load_manifest(Path(args.manifest))
    if not manifest and args.prefix:
        # best-effort: try to fetch any latest manifest_* from the bucket
        # (simple heuristic; for a 1–2 day project this is fine)
        resp = client.list_objects_v2(Bucket=args.bucket, Prefix=args.prefix.rstrip('/') + "/")
        candidates = []
        for obj in resp.get("Contents", []):
            if os.path.basename(obj["Key"]).startswith("manifest_") and obj["Key"].endswith(".json"):
                candidates.append(obj["Key"])
        if candidates:
            latest = sorted(candidates)[-1]
            data = client.get_object(Bucket=args.bucket, Key=latest)["Body"].read()
            manifest = json.loads(data.decode())

    if not manifest:
        print("No manifest available. Attempting blind restore of all objects under prefix...")
        paginator = client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=args.bucket, Prefix=args.prefix or ""):
            for o in page.get("Contents", []):
                key = o["Key"]
                rel = key[len(args.prefix)+1:] if args.prefix and key.startswith(args.prefix + "/") else key
                out = target / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                print(f"[restore] {rel}")
                if not args.dry_run:
                    client.download_file(args.bucket, key, str(out))
        return

    # Restore using manifest
    for rel, meta in manifest["files"].items():
        key = meta["key"]
        out = target / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        print(f"[restore] {rel}")
        if args.dry_run: continue
        client.download_file(args.bucket, key, str(out))

        if args.verify:
            # Verify restored file matches recorded sha256
            if sha256_file(out) != meta["sha256"]:
                print(f"  - verify: MISMATCH for {rel}", file=sys.stderr)
            else:
                print("  - verify: OK")

def main():
    p = argparse.ArgumentParser(description="S3/MinIO backup with versioning and integrity checks")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--bucket", required=True, help="S3/MinIO bucket name")
    common.add_argument("--endpoint", default=None, help="Custom S3 endpoint (e.g., http://127.0.0.1:9000 for MinIO)")
    common.add_argument("--prefix", default="", help="Key prefix inside bucket")
    common.add_argument("--manifest", default="manifest.json", help="Local manifest path")
    common.add_argument("--dry-run", action="store_true", help="Plan only; no changes")
    common.add_argument("--verify", action="store_true", help="Re-download to verify hashes after upload/restore")

    b = sub.add_parser("backup", parents=[common])
    b.add_argument("--source", required=True, help="Folder to back up")
    b.add_argument("--force", action="store_true", help="Ignore manifest and upload all")
    b.add_argument("--storage-class", default=None, help="e.g., STANDARD_IA, ONEZONE_IA (AWS)")

    r = sub.add_parser("restore", parents=[common])
    r.add_argument("--restore-target", default="restore", help="Where to restore files")

    args = p.parse_args()
    if args.cmd == "backup":
        backup(args)
    elif args.cmd == "restore":
        restore(args)

if __name__ == "__main__":
    main()
