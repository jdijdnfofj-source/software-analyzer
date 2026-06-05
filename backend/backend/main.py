from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import os
import hashlib
import psutil

app = FastAPI(title="Software Analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def hash_file(file_path: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <html>
    <head><title>Software Analyzer</title></head>
    <body style="font-family:Arial; padding:20px;">
        <h1>Software Analyzer</h1>
        <button onclick="scan()">Scan</button>
        <pre id="out"></pre>
        <script>
        async function scan() {
            const res = await fetch('/api/scan');
            const data = await res.json();
            document.getElementById('out').textContent = JSON.stringify(data, null, 2);
        }
        </script>
    </body>
    </html>
    """

@app.get("/api/scan")
async def scan():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr:
            connections.append({
                "local": str(conn.laddr) if conn.laddr else "",
                "remote": str(conn.raddr),
                "status": conn.status,
                "pid": conn.pid
            })

    files = []
    for root, dirs, file_names in os.walk("."):
        for name in file_names:
            path = os.path.join(root, name)
            if os.path.isfile(path):
                try:
                    files.append({
                        "file": path,
                        "sha256": hash_file(path)
                    })
                except:
                    pass

    return {
        "status": "ok",
        "files": files[:100],
        "connections": connections[:100]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
