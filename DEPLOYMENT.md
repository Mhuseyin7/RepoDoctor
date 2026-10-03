# Production deployment

RepoDoctor self-hosted bir stack'tir. Bu repository tek başına public bir service başlatmaz: çalıştıracağınız Linux server, DNS kaydı ve domain sizin kontrolünüzde olmalıdır. Stack; PostgreSQL, API, Next.js dashboard ve Caddy reverse proxy içerir.

## Gereksinimler

- Docker Engine ve Docker Compose plugin bulunan Linux server
- Domain için server'ın public IP adresine yönelen `A` veya `AAAA` DNS kaydı
- Firewall üzerinde TCP `80` ve `443` izinleri
- Scan edilecek repository'leri içeren, server üzerinde erişilebilir bir directory

## İlk kurulum

```bash
git clone https://github.com/Mhuseyin7/RepoDoctor.git
cd RepoDoctor
cp .env.example .env
mkdir -p sample-repositories
```

`.env` içindeki değerleri düzenleyin:

- `POSTGRES_PASSWORD`: uzun, benzersiz database password.
- `CADDY_SITE_ADDRESS`: production'da domain adınız; örneğin `repodoctor.example.com`. Caddy bu değer bir domain olduğunda HTTPS certificate'ını otomatik alır ve yeniler.
- `CADDY_BASIC_AUTH_USER`: dashboard kullanıcısı.
- `CADDY_BASIC_AUTH_HASH`: aşağıdaki komutla üretilen bcrypt hash. Plain-text password kesinlikle `.env` dosyasına yazılmaz.

```bash
docker run --rm caddy:2.10.2-alpine caddy hash-password --plaintext 'uzun-ve-benzersiz-bir-password'
```

Sadece private network'te HTTP kullanmak için `CADDY_SITE_ADDRESS=:80` tanımlanabilir. Public Internet için gerçek domain kullanın; HTTPS'i devre dışı bırakmayın.

Stack'i başlatın:

```bash
docker compose up --build -d
docker compose ps
curl -u "admin:YOUR_PASSWORD" https://repodoctor.example.com/api/health
```

İlk açılışta API, Alembic migration'larını uygular. `gateway`, `api` ve `web` servislerinin `healthy` durumda olduğunu `docker compose ps` ile kontrol edin. Dashboard ve API, Basic Auth arkasındadır; repository path'leri veya finding'ler anonymous kullanıcılar tarafından okunamaz.

## Repository mount ve scan scope

`docker-compose.yml` varsayılan olarak `./sample-repositories` directory'sini container içindeki `/repositories` konumuna read-only mount eder. Gerçek repository directory'nizi bu konuma kopyalayın veya compose dosyasındaki volume kaynağını değiştirin. `REPODOCTOR_ALLOWED_ROOTS=/repositories` sınırı dışındaki path'ler API tarafından reddedilir.

Container'a secret içeren veya yazılabilir geniş host mount'ları vermeyin. RepoDoctor source code'u çalıştırmaz; yine de yalnızca güvenilir kullanıcıların erişebildiği repository'leri tarayın.

## Operasyonlar

Güncelleme:

```bash
git pull --ff-only
docker compose up --build -d
docker compose ps
```

PostgreSQL backup:

```bash
docker compose exec -T database pg_dump -U repodoctor repodoctor > repodoctor-backup.sql
```

Restore yapmadan önce mevcut backup'ı saklayın. Restore işlemi database verisini değiştirir:

```bash
docker compose exec -T database psql -U repodoctor -d repodoctor < repodoctor-backup.sql
```

Log inceleme:

```bash
docker compose logs --tail=200 api web gateway
```

Stack'i durdurmak için `docker compose down` kullanın. Database verisini korur. `docker compose down -v` database volume'ünü de siler; yalnızca doğrulanmış backup varsa kullanın.

## Rollback

Önce çalışan commit SHA'sını not edin. Sorunlu bir update'ten sonra güvenli bir önceki commit'e dönüp image'ları yeniden oluşturun:

```bash
git checkout <known-good-commit>
docker compose up --build -d
```

Database migration'ları ileri uyumlu olmayabilir. Bu nedenle production update öncesinde backup alın; uygulama rollback'i sırasında migration rollback'ini otomatik çalıştırmayın.
