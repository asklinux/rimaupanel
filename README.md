# RimauPanel (Go + SQLite)

Sistem web asas menggunakan Go dengan login berasaskan SQLite dan dashboard SB Admin 2.

## Ciri Semasa
- Login/logout pengguna
- SQLite untuk jadual `users` dan `sessions`
- Dashboard status sistem:
  - CPU usage
  - Memory usage
  - Maklumat OS (nama OS, kernel, hostname, uptime)

## Keperluan
- Go 1.22+

## Install Dengan Repos
Debian/ubuntu

wget https://tunnelbiz.com/repo/rimaupanel/rimaupanel-repo_1.0.0_all.deb

chmod +x rimaupanel-repo_1.0.0_all.deb

apt install rimaupanel-repo_1.0.0_all.deb

RHEL/ROCKY

dnf install https://tunnelbiz.com/repo/rocky/rimaupanel-repo-1.0-1.el8.noarch.rpm

## Jalankan Local
```bash
make tidy
make fmt
make run
```
Akses: `http://localhost:8000`

Login default (auto-seed bila DB kosong):
- Username: `admin`
- Password: `admin123`

## Build Binary
Build ke folder lokal:
```bash
make build
```

Build terus ke `/opt/rimaupanel`:
```bash
make build-opt
```

Jika gagal sebab permission, jalankan dengan sudo:
```bash
sudo mkdir -p /opt/rimaupanel
sudo go build -o /opt/rimaupanel/rimaupanel ./cmd/rimaupanel
```

## Konfigurasi Env
- `RIMAUPANEL_ADDR` (default `:8000`)
- `RIMAUPANEL_DB` (default `./data/rimaupanel.db`)
- `RIMAUPANEL_SESSION_HOURS` (default `24`)
- `RIMAUPANEL_ADMIN_USER` (default `admin`)
- `RIMAUPANEL_ADMIN_PASS` (default `admin123`)
