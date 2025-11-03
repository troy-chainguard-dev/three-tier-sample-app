# three-tier-sample-app

<div align="center">
  <img src="img/qr-code.png" alt="Scan to access repository" width="200"/>
  <p><em>Scan to access this repository!</em></p>
</div>

---

This is a sample web application showcasing a multi-tier architecture using **Node.js**, **Python (Flask)**, **PostgreSQL**, and **nginx**.

We will walk through and build this app two different ways and then use a Python script with grype to compare the two deployments:
- **Legacy version** with traditional upstream container images.
- **Chainguard version** using minimal, secure-by-default, zero to near-zero CVE container images.

## Architecture

<div align="center">
  <img src="img/architecture_light.png" alt="Multi-tier architecture diagram" width="100%" style="border-radius: 15px;"/>
</div>

---

## Getting Started

### Prerequisites
- Terminal access
- [Docker](https://www.docker.com/) (container runtime)
- [Docker Compose](https://docs.docker.com/compose/) (multi-container build and orchestration)
- [grype](https://github.com/anchore/grype) (for scanning container images)
- Python 3.7+ (for vulnerability reporting)
- Clone this directory and `cd` into it from your terminal: 
```bash
cd three-tier-sample-app
```

### Python Virtual Environment Setup

Create and activate a Python virtual environment for the scanning tools.  Example where the Python binary is `python3`:

```
python3 -m venv venv
```
For `bash/zsh` based terminals:
```
source venv/bin/activate
```

For Windows terminals:
```
.\venv\Scripts\activate
```
Install Python dependencies:

For `bash/zsh` based terminals:
```
pip install -r scanners/requirements.txt
```
For Windows terminals:
```
pip install -r .\scanners\requirements.txt
```
**Note:** The environment will need to be activated to run the scanners in later steps so we can work within the virtual Python environment for the remainder of the steps 

---

## 1. Build and Run the Legacy Version

### Container Images Used

<table>
<tr>
<td width="45%">
  <img src="img/legacy-images-simple.png" alt="Legacy container images" width="100%" style="border-radius: 15px;"/>
</td>
<td width="55%" valign="top">
  <br/>
  <h4>🔗 Upstream Docker Images:</h4>
  <ul>
    <li><strong>nginx:</strong> <a href="https://hub.docker.com/_/nginx">docker.io/library/nginx:latest</a></li>
    <li><strong>Node.js:</strong> <a href="https://hub.docker.com/_/node">docker.io/library/node:latest</a></li>
    <li><strong>Python:</strong> <a href="https://hub.docker.com/_/python">docker.io/library/python:latest</a></li>
    <li><strong>PostgreSQL:</strong> <a href="https://hub.docker.com/_/postgres">docker.io/library/postgres:latest</a></li>
  </ul>
</td>
</tr>
</table>

First we will use docker compose to build the app using the legacy images. The following `docker compose` command will recognize the `docker-compose.yaml` file in the root project directory and build custom images for each component based on public upstream base images from Docker Hub (node:latest, python:latest, nginx:latest, postgres:latest).  **Note that the --build flag forces Docker to rebuild the images, and if the base images aren't cached locally, Docker will pull them from Docker Hub, which may take a long time on a poor network connection!**

```bash
docker compose up -d --build
```

Expected output:
```
[+] Running 8/8
 ✔ backend Built                           0.0s
 ✔ frontend Built                          0.0s
 ✔ nginx Built                             0.0s
 ✔ Network three-tier-sample-app_default    0.1s
 ✔ Container legacy-db Started             0.3s
 ✔ Container legacy-backend Started        0.3s
 ✔ Container legacy-frontend Started       0.3s
 ✔ Container legacy-nginx Started          0.3s
```

### Verify It's Running

To ensure the containers are running:
```bash
docker ps
```

Expected output:
```
CONTAINER ID   IMAGE                              STATUS         PORTS                    NAMES
9da02e3b2f76   three-tier-nginx-legacy:latest      Up 3 minutes   0.0.0.0:80->80/tcp       legacy-nginx
26e1462fabb0   three-tier-frontend-legacy:latest   Up 3 minutes                            legacy-frontend
3cc427943561   three-tier-backend-legacy:latest    Up 3 minutes   0.0.0.0:5000->5000/tcp   legacy-backend
22f51e9cdff9   three-tier-db-legacy:latest         Up 3 minutes   0.0.0.0:5432->5432/tcp   legacy-db
```

Let's start a log view of our containers before we test our app:
```
docker compose logs -f
```

Open [http://localhost:80](http://localhost:80) in your browser to view the website:

<div align="center">
  <img src="img/website.png" alt="Course Registration Website" style="border-radius: 15px;"/>
</div>

Refresh the page and click some 'Register' buttons and look at our logs to see the output.  We should see all the various components receiving and passing traffic:

```
legacy-db        | 2025-10-10 15:38:12.260 UTC [1] LOG:  database system is ready to accept connections
legacy-frontend  | [2025-10-10T15:38:17.514Z] GET / - 172.20.0.5
legacy-nginx     | 172.20.0.1 - - [10/Oct/2025:15:38:17 +0000] "GET / HTTP/1.1" 200 279 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15"
legacy-db        | 2025-10-10 15:38:17.558 UTC [69] LOG:  connection received: host=172.20.0.3 port=53718
legacy-db        | 2025-10-10 15:38:17.568 UTC [69] LOG:  connection authenticated: identity="user" method=scram-sha-256 (/var/lib/postgresql/data/pg_hba.conf:128)
legacy-db        | 2025-10-10 15:38:17.568 UTC [69] LOG:  connection authorized: user=user database=chaiku
legacy-db        | 2025-10-10 15:38:17.574 UTC [69] LOG:  statement: BEGIN
legacy-db        | 2025-10-10 15:38:17.575 UTC [69] LOG:  statement: SELECT id, name, credits FROM courses
legacy-db        | 2025-10-10 15:38:17.576 UTC [69] LOG:  disconnection: session time: 0:00:00.018 user=user database=chaiku host=172.20.0.3 port=53718
legacy-backend   | 172.20.0.5 - - [10/Oct/2025 15:38:17] "GET /courses HTTP/1.0" 200 -
legacy-nginx     | 172.20.0.1 - - [10/Oct/2025:15:38:17 +0000] "GET /api/courses HTTP/1.1" 200 298 "http://localhost/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15"
legacy-db        | 2025-10-10 15:38:18.867 UTC [70] LOG:  connection received: host=172.20.0.3 port=53726
```
This confirms that our microservice app is up and operational!

### Scan Legacy Images for CVEs

Now let's scan our running containers for security vulnerabilities:

Activate your virtual environment if you haven't already (macOS/Linux):
```bash
source venv/bin/activate
```

Run the scanner:
```bash
python3 scanners/scan-and-report.py
```

This single command will:
- ✅ Detect all running containers from `docker compose`
- ✅ Use Grype to scan each container image for known CVEs
- ✅ Generate CSV reports with vulnerability data
- ✅ Auto-generate formatted Excel reports with charts and formatting

**Output files in `./scanners/scan-results/`:**
- `grype-legacy-images.csv` - Raw vulnerability data
- `grype-legacy-images.xlsx` - Formatted Excel report with:
  - Executive summary with statistics and pie charts
  - Color-coded severity levels (Critical=Red, High=Orange, etc.)
  - Hyperlinked CVE IDs (click to view details on NIST NVD)
  - Separate worksheets for each severity level
  - Per-image breakdown sheets (including images with 0 vulnerabilities)
  - Auto-filtering and sortable columns

---

## 2. Tear Down the Legacy Stack

To clean everything, including volumes:

```bash
docker compose down -v
```

---

## 3. Build and Run the Chainguard Version

### Container Images Used

<table>
<tr>
<td width="45%">
  <img src="img/chainguard-images-simple.png" alt="Chainguard container images" width="100%" style="border-radius: 15px;"/>
</td>
<td width="55%" valign="top">
  <br/>
  <h4>🐙 Chainguard Images:</h4>
  <ul>
    <li><strong>nginx:</strong> <a href="https://images.chainguard.dev/directory/image/nginx/overview">cgr.dev/chainguard/nginx:latest</a></li>
    <li><strong>Node.js:</strong> <a href="https://images.chainguard.dev/directory/image/node/overview">cgr.dev/chainguard/node:latest</a></li>
    <li><strong>Python:</strong> <a href="https://images.chainguard.dev/directory/image/python/overview">cgr.dev/chainguard/python:latest</a></li>
    <li><strong>PostgreSQL:</strong> <a href="https://images.chainguard.dev/directory/image/postgres/overview">cgr.dev/chainguard/postgres:latest</a></li>
  </ul>
  <p><em>✅ Zero to near-zero CVEs • Minimal attack surface</em></p>
</td>
</tr>
</table>

We will now use Docker Compose to create our Chainguard version of the app by pointing to a specific compose file called `docker-compose-chainguard.yaml`  This compose file will reference the specific `cgr.dev/chainguard/<images>` listed above

```bash
docker compose -f docker-compose-chainguard.yaml up -d --build
```

Expected output:
```
[+] Running 8/8
 ✔ backend Built                           0.0s
 ✔ frontend Built                          0.0s
 ✔ nginx Built                             0.0s
 ✔ Network three-tier-sample-app_default    0.1s
 ✔ Container three-tier-db-cg Started       0.3s
 ✔ Container cg-backend Started            0.4s
 ✔ Container cg-frontend Started           0.4s
 ✔ Container cg-nginx Started              0.4s
```

### Verify It's Running

To ensure the Chainguard-based containers are running (notice the **cg** tags on container names):
```bash
docker ps
```

Expected output:
```
CONTAINER ID   IMAGE                           STATUS         PORTS                    NAMES
476abfd23815   three-tier-nginx-cg:latest       Up 5 minutes   0.0.0.0:80->80/tcp       cg-nginx
4a12bab4e30b   three-tier-frontend-cg:latest    Up 5 minutes                            cg-frontend
5151ef168869   three-tier-backend-cg:latest     Up 5 minutes   0.0.0.0:5000->5000/tcp   cg-backend
949fdcf98c9d   three-tier-db-cg:latest          Up 5 minutes   0.0.0.0:5432->5432/tcp   three-tier-db-cg
```

Let's start a log view of our containers before we test our app:
```
docker compose logs -f
```
Open [http://localhost:80](http://localhost:80) in your browser to view the website:

<div align="center">
  <img src="img/website.png" alt="Course Registration Website" style="border-radius: 15px;"/>
</div>

Refresh the page and click some 'Register' buttons and look at our logs to see the output. We should see all the various components receiving and passing traffic:

```
three-tier-db-cg  | 2025-10-10 15:29:49.178 UTC [1] LOG:  database system is ready to accept connections
cg-frontend      | [2025-10-10T15:29:53.667Z] GET / - 172.20.0.5
cg-nginx         | 172.20.0.1 - - [10/Oct/2025:15:29:53 +0000] "GET / HTTP/1.1" 200 279 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15"
cg-backend       | 172.20.0.5 - - [10/Oct/2025 15:29:53] "GET /courses HTTP/1.0" 200 -
cg-nginx         | 172.20.0.1 - - [10/Oct/2025:15:29:53 +0000] "GET /api/courses HTTP/1.1" 200 298 "http://localhost/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15"
cg-backend       | 172.20.0.5 - - [10/Oct/2025 15:29:55] "POST /register HTTP/1.0" 201 -
cg-nginx         | 172.20.0.1 - - [10/Oct/2025:15:29:55 +0000] "POST /api/register HTTP/1.1" 201 43 "http://localhost/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15"
cg-backend       | 172.20.0.5 - - [10/Oct/2025 15:29:58] "POST /register HTTP/1.0" 201 -
cg-nginx         | 172.20.0.1 - - [10/Oct/2025:15:29:58 +0000] "POST /api/register HTTP/1.1" 201 43 "http://localhost/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15"
```

This confirms that our Chainguard-based microservice app is up and operational!

### Scan Chainguard Images for CVEs

Now let's scan the Chainguard images for security vulnerabilities:

```bash
python3 scanners/scan-and-report.py
```

This will generate the same reports as above (CSV and Excel), plus an additional **comparison report** that shows:
- 📊 Executive summary with reduction metrics and % improvements
- 📈 Visual comparison of vulnerability distributions
- 💡 Key takeaways highlighting security wins

### Image Comparison: Legacy vs Chainguard

Here's a snapshot comparison from a recent scan on 10/6/25 (your results may vary based on scan date and host system architecture):

| Component | Legacy Image | Size | CVEs | Chainguard Image | Size | CVEs |
|-----------|-------------|------|------|------------------|------|------|
| **nginx** | `nginx:latest` | ~187 MB | 150+ | `cgr.dev/chainguard/nginx:latest` | ~50 MB | 0-2 |
| **Frontend** | `node:latest` | ~1.1 GB | 200+ | `cgr.dev/chainguard/node:latest` | ~75 MB | 0-2 |
| **Backend** | `python:latest` | ~1.0 GB | 180+ | `cgr.dev/chainguard/python:latest` | ~50 MB | 0-1 |
| **Database** | `postgres:latest` | ~420 MB | 120+ | `cgr.dev/chainguard/postgres:latest` | ~280 MB | 0-1 |
| **TOTAL** | | **~2.7 GB** | **650+** | | **~455 MB** | **0-6** |

**Key Takeaways:**
- 🔻 **83% reduction in total image size** (2.7 GB → 455 MB)
- 🔻 **99% reduction in CVEs** (650+ → 0-6)

---

## 4. Tear Down the Chainguard Stack

To clean everything, including volumes:

```bash
docker compose down -v
```

---

## Migrating From Upstream to Chainguard

Let's take a closer look at how Chainguard images differ from upstream images by comparing the Dockerfiles for Python and some image details.

### Legacy Dockerfile (Upstream Python)

```dockerfile
FROM python:latest

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "wsgi.py"]
```
**Resulting Image:**
```bash
docker images | grep three-tier-backend-legacy
```
```
three-tier-backend-legacy latest 4deda6071707 2 days ago 1.64GB
```

**Why is this image so big?**  

The `python:latest` image is built on top of **Debian Linux** (specifically Debian Trixie), which includes a full operating system with hundreds of packages that aren't needed for running Python applications. Let's examine what's inside:

Check the base OS:
```bash
docker run --rm python:latest cat /etc/os-release
```

```
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
...
```

A Grype scan reveals the scale of unnecessary packages:

```
grype python:latest
   ...
   ├── ✔ Packages                        [477 packages]
   ├── ✔ Executables                     [1,403 executables]
   ├── ✔ File metadata                   [21,671 locations]
   └── ✔ File digests                    [21,671 files]
```

**Where do all these packages come from?** The base Debian OS brings most of them:

List installed debian packages in python:latest
```bash
docker run --rm python:latest dpkg -l | wc -l
```
```
472 packages
```

**The problem:** Most of these 477 packages are inherited from Debian and have nothing to do with Python. They include:
- 📦 Package managers (apt, dpkg)
- 🛠️ Build tools (gcc, make, perl)  
- 📚 System libraries (systemd, pam, glibc utilities)
- 🐚 Shells and utilities (bash, grep, sed, coreutils)
- 🔧 Services and daemons you'll never use

**Each unnecessary package = more CVEs, more attack surface, more storage.**

### Chainguard Dockerfile (Hardened Python)

```dockerfile
FROM cgr.dev/chainguard/python:latest-dev AS builder

WORKDIR /app

COPY requirements.txt .

RUN python -m venv /app/venv && \ 
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM cgr.dev/chainguard/python:latest

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PATH="/venv/bin:$PATH"

COPY . .
COPY --from=builder /app/venv /venv

ENTRYPOINT [ "python", "wsgi.py" ]
```

**Resulting Image:**
```bash
docker images | grep three-tier-backend-cg
```
```
three-tier-backend-cg latest 526d24399c50   23 hours ago    126MB
```

**What makes Chainguard different?**

Chainguard images are built on **[Wolfi](https://github.com/wolfi-dev/)**, a Linux _undistro_ designed specifically for containers - NOT a traditional Linux distribution like Debian.

Prove it's Wolfi (using -dev variant since runtime has no shell):
```bash
docker run --rm --entrypoint /bin/sh cgr.dev/chainguard/python:latest-dev -c "cat /etc/os-release"
```

```
ID=wolfi
NAME="Wolfi"
PRETTY_NAME="Wolfi"
HOME_URL="https://wolfi.dev"
```

**The runtime image is truly distroless** - it doesn't even have a shell.

Try to run a shell in the production runtime image:
```bash
docker run --rm --entrypoint /bin/sh cgr.dev/chainguard/python:latest -c "echo test"
```
```
exec: "/bin/sh": stat /bin/sh: no such file or directory
```

**Package comparison: Debian vs Wolfi runtime**

Debian-based Python runtime:
```bash
docker run --rm python:latest dpkg -l | grep "^ii" | wc -l
```
```
467 packages
```

Chainguard Python runtime (Wolfi-based):
```bash
grype cgr.dev/chainguard/python:latest
```
```
 ✔ Cataloged contents
   ├── ✔ Packages                        [22 packages]
   ├── ✔ Executables                     [27 executables]
```

The Chainguard runtime has only **22** packages - just Python and essential dependencies. The Debian runtime has **467** packages including full OS tools like shells, package managers, and build tools.

**The Chainguard approach:**
- 🎯 **Wolfi-based**: Purpose-built minimal OS designed for containers, not bloated Debian/Ubuntu
- 🗑️ **Distroless runtime**: No shell, no package manager, no unnecessary tools
- 📦 **95% fewer packages**: 22 vs 467 (only what Python needs to run)
- 🔒 **Non-root by default**: Runs as user `65532` (nonroot)
- 🏗️ **Multi-stage build**: Use `-dev` image to build, minimal runtime for production
- 🔄 **Daily updates**: Automated rebuilds with latest security patches
- 📋 **Built-in SBOMs**: Cryptographically signed software bill of materials for compliance

---

## Summary: By The Numbers

| Metric | Upstream Images | Chainguard Images |
|--------|----------------|-------------------|
| **Total CVEs** | 650+ | 0-6 |
| **Total Size** | ~2.7 GB | ~455 MB |
| **Packages (Python)** | 467 | 22 |
| **Attack Surface** | Full OS with shells, package managers, build tools | Distroless - application runtime only |

**The bottom line:** In production, every CVE means security incidents, compliance violations, and emergency patching. Chainguard Images eliminate 99% of these concerns by shipping only what your application needs to run—nothing more.

---

## Further Reading

Want to learn more about Chainguard Images and secure container practices?

- 📚 **[Chainguard Images Directory](https://images.chainguard.dev/)** - Explore all available Chainguard images with detailed documentation, SBOMs, and security information
- 🐍 **[Python Image Comparison](https://images.chainguard.dev/directory/image/python/compare)** - Deep dive into the Python image architecture, variants, and security benefits
- 🎓 **[Chainguard Academy](https://edu.chainguard.dev/)** - Free courses and resources for learning about container security, supply chain security, and cloud-native best practices

---