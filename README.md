# 🗄️ S3 Backup Tool

A simple Python-based **backup and restore system** that pushes local files to **AWS S3 (or any S3-compatible storage like MinIO)** with:

- ✅ **Incremental backups** (only changed files upload)  
- ✅ **SHA-256 integrity checks** (trust but verify)  
- ✅ **Versioning support** (recover older copies)  
- ✅ **Dry-run mode** (see what would happen before running)  
- ✅ **Restore command** (pulls back the latest versions of files)  

This project demonstrates **automation, reliability, and cloud API skills** — perfect for Site Reliability Engineer (SRE) scenarios.  

---

## 📦 Features

- **Backup**
  - Detects changes using SHA-256 hashes  
  - Uploads only modified/new files  
  - Stores file metadata in a `manifest.json` locally and in S3  
  - Optionally re-downloads files after upload to verify integrity  

- **Restore**
  - Restores the latest versions of files to a target directory  
  - Can integrity-check restored files against hashes  

- **Safety**
  - Uses S3 **bucket versioning** for rollback/recovery  
  - Skips unchanged files to save bandwidth and costs  
  - Supports `--dry-run` to preview actions  

---

## ⚙️ Requirements

- Python **3.8+** (tested on Windows 11 with Python 3.11)  
- AWS CLI configured with an IAM user that has S3 permissions  
- Dependencies:
