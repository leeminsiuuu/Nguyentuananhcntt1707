from flask import Flask, request, send_file, jsonify, render_template_string, redirect, url_for
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os
import uuid
import base64

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

KEY_FILE = "private.pem"
if not os.path.exists(KEY_FILE):
    key = RSA.generate(2048)
    with open("private.pem", "wb") as f:
        f.write(key.export_key())
    with open("public.pem", "wb") as f:
        f.write(key.publickey().export_key())
else:
    key = RSA.import_key(open("private.pem").read())
public_key = key.publickey()

files_db = {}
handshake_status = {"status": "idle"}

# --------------------- Giao diện gửi ---------------------
SEND_HTML = """
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <title>🔐 Gửi File Ký Số RSA</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
  <style>
    body {
      background: linear-gradient(to right, #74ebd5, #acb6e5);
      min-height: 100vh;
    }
    .card {
      box-shadow: 0 0 20px rgba(0,0,0,0.15);
    }
    textarea {
      background-color: #f8f9fa;
    }
  </style>
</head>
<body>
<div class="container py-5">
  <div class="card p-4">
    <h2 class="text-center text-primary mb-4">📤 Gửi File Kèm Chữ Ký Số</h2>
    <form id="sendForm">
      <div class="mb-3">
        <label class="form-label">📁 Chọn file cần gửi:</label>
        <input type="file" class="form-control" id="sendFile" required>
      </div>

      <div class="mb-3">
        <label class="form-label">🎙️ Hoặc ghi âm trực tiếp:</label><br>
        <button type="button" class="btn btn-danger me-2" id="recordBtn">🔴 Bắt đầu Ghi âm</button>
        <button type="button" class="btn btn-secondary" id="stopBtn" disabled>⏹️ Dừng</button>
        <audio id="audioPreview" controls class="mt-2" style="display:none;"></audio>
      </div>

      <div class="mb-3">
        <button type="button" class="btn btn-warning" id="handshakeBtn">🤝 Bắt tay (Hello)</button>
        <button type="button" class="btn btn-info" id="checkHandshakeBtn">🔍 Kiểm tra trạng thái</button>
        <span id="handshakeStatus" class="ms-2 text-success"></span>
      </div>

      <div class="d-flex justify-content-between">
        <button type="submit" class="btn btn-success">🚀 Gửi File</button>
        <a href="/receive" class="btn btn-outline-dark">🔽 Đến trang Nhận File</a>
      </div>
    </form>
    <div id="sendStatus" class="mt-4"></div>
  </div>
</div>

<script>
const sendForm = document.getElementById('sendForm');
const sendStatus = document.getElementById('sendStatus');
const fileInput = document.getElementById('sendFile');

const recordBtn = document.getElementById('recordBtn');
const stopBtn = document.getElementById('stopBtn');
const audioPreview = document.getElementById('audioPreview');

let mediaRecorder;
let audioChunks = [];

recordBtn.onclick = async () => {
  if (!navigator.mediaDevices) {
    alert("Trình duyệt của bạn không hỗ trợ ghi âm!");
    return;
  }
  const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  mediaRecorder = new MediaRecorder(stream);
  audioChunks = [];

  mediaRecorder.ondataavailable = e => {
    audioChunks.push(e.data);
  };

  mediaRecorder.onstop = () => {
    const blob = new Blob(audioChunks, { type: 'audio/webm' });
    audioPreview.src = URL.createObjectURL(blob);
    audioPreview.style.display = 'block';

    const audioFile = new File([blob], "recorded_audio.webm", { type: 'audio/webm' });
    const dt = new DataTransfer();
    dt.items.add(audioFile);
    fileInput.files = dt.files;
  };

  mediaRecorder.start();
  recordBtn.disabled = true;
  stopBtn.disabled = false;
};

stopBtn.onclick = () => {
  if (mediaRecorder && mediaRecorder.state !== "inactive") {
    mediaRecorder.stop();
    recordBtn.disabled = false;
    stopBtn.disabled = true;
  }
};

const handshakeBtn = document.getElementById('handshakeBtn');
const checkHandshakeBtn = document.getElementById('checkHandshakeBtn');
const handshakeStatus = document.getElementById('handshakeStatus');

handshakeBtn.onclick = async () => {
  const resp = await fetch('/api/handshake/send', { method: 'POST' });
  const data = await resp.json();
  handshakeStatus.textContent = "Trạng thái: " + data.status;
};

checkHandshakeBtn.onclick = async () => {
  const resp = await fetch('/api/handshake/status');
  const data = await resp.json();
  handshakeStatus.textContent = "Trạng thái: " + data.status;
};

sendForm.addEventListener('submit', async e => {
  e.preventDefault();
  if (fileInput.files.length === 0) {
    alert("Vui lòng chọn file hoặc ghi âm.");
    return;
  }

  const checkResp = await fetch('/api/handshake/status');
  const checkData = await checkResp.json();
  if (checkData.status !== "ready") {
    alert("Người nhận chưa sẵn sàng (status chưa ready). Vui lòng kiểm tra lại handshake!");
    return;
  }

  const file = fileInput.files[0];
  const formData = new FormData();
  formData.append("file", file);

  sendStatus.innerHTML = "<div class='text-info'>⏳ Đang gửi file...</div>";

  const resp = await fetch('/api/upload', { method: 'POST', body: formData });
  const data = await resp.json();

  if (resp.ok) {
    sendStatus.innerHTML = `
      <div class="alert alert-success">
        ✅ Gửi file thành công!<br>
        <strong>🆔 Mã File:</strong> ${data.file_id}<br>
        <strong>✍️ Chữ ký (Base64):</strong>
        <textarea class="form-control mt-2" rows="3" readonly>${data.signature}</textarea>
      </div>
    `;
  } else {
    sendStatus.innerHTML = `<div class="alert alert-danger">❌ Lỗi khi gửi file!</div>`;
  }
});
</script>
</body>
</html>
"""

# --------------------- Giao diện nhận ---------------------
RECEIVE_HTML = """
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <title>📥 Nhận & Kiểm Tra File</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
  <style>
    body {
      background: linear-gradient(to right, #f6d365, #fda085);
      min-height: 100vh;
    }
    .card {
      box-shadow: 0 0 20px rgba(0,0,0,0.15);
    }
  </style>
</head>
<body>
<div class="container py-5">
  <div class="card p-4">
    <h2 class="text-center text-danger mb-4">📥 Nhận & Kiểm Tra File</h2>
    <div class="mb-3">
      <button type="button" class="btn btn-warning" id="checkHandshakeBtn">🔍 Kiểm tra Handshake</button>
      <button type="button" class="btn btn-success" id="acceptHandshakeBtn">✅ Phản hồi Ready</button>
      <span id="checkStatus" class="ms-2"></span>
    </div>
    <div class="d-flex justify-content-end mb-3">
      <a href="/send" class="btn btn-outline-dark">🔼 Quay lại Gửi File</a>
    </div>
    <ul id="fileList" class="list-group mt-3"></ul>
    <div id="verifyStatus" class="mt-3"></div>
  </div>
</div>

<script>
const checkHandshakeBtn = document.getElementById('checkHandshakeBtn');
const acceptHandshakeBtn = document.getElementById('acceptHandshakeBtn');
const checkStatus = document.getElementById('checkStatus');

checkHandshakeBtn.onclick = async () => {
  const resp = await fetch('/api/handshake/status');
  const data = await resp.json();
  checkStatus.textContent = "Trạng thái: " + data.status;
};

acceptHandshakeBtn.onclick = async () => {
  const resp = await fetch('/api/handshake/accept', { method: 'POST' });
  const data = await resp.json();
  checkStatus.textContent = "Trạng thái mới: " + data.status;
};

async function loadFileList() {
  const resp = await fetch('/api/files');
  const files = await resp.json();
  const fileList = document.getElementById('fileList');
  fileList.innerHTML = '';

  if (files.length === 0) {
    fileList.innerHTML = '<li class="list-group-item text-muted">📂 Chưa có file nào được tải lên.</li>';
    return;
  }

  files.forEach(f => {
    const li = document.createElement('li');
    li.className = 'list-group-item d-flex justify-content-between align-items-center';
    li.innerHTML = `
      <div>
        <strong>📎 ${f.filename}</strong><br>
        <small>🆔 ID: ${f.file_id}</small><br>
        <small>⏰ ${new Date(f.timestamp * 1000).toLocaleString()}</small>
      </div>
      <div>
        <button class="btn btn-sm btn-outline-success me-2" onclick="downloadFile('${f.file_id}')">⬇️ Tải</button>
        <button class="btn btn-sm btn-outline-info" onclick="verifyFile('${f.file_id}')">🔍 Kiểm Tra</button>
      </div>
    `;
    fileList.appendChild(li);
  });
}

async function downloadFile(file_id) {
  window.open(`/download/${file_id}`, '_blank');
}

async function verifyFile(file_id) {
  const verifyStatus = document.getElementById('verifyStatus');
  verifyStatus.innerHTML = "🔄 Đang kiểm tra chữ ký...";
  const resp = await fetch(`/api/verify/${file_id}`);
  const data = await resp.json();
  if (data.valid) {
    verifyStatus.innerHTML = '<div class="alert alert-success">✅ Chữ ký hợp lệ. File an toàn.</div>';
  } else {
    verifyStatus.innerHTML = '<div class="alert alert-danger">❌ Chữ ký không hợp lệ hoặc file đã bị chỉnh sửa!</div>';
  }
}

loadFileList();
</script>
</body>
</html>
"""

# --------------------- Các route Flask ---------------------

@app.route("/")
def home():
    return redirect(url_for("send"))

@app.route("/send")
def send():
    return render_template_string(SEND_HTML)

@app.route("/receive")
def receive():
    return render_template_string(RECEIVE_HTML)

@app.route("/api/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file"}), 400

    data = file.read()
    hash_obj = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(hash_obj)
    signature_b64 = base64.b64encode(signature).decode()

    file_id = str(uuid.uuid4())
    filename = file.filename
    file_path = os.path.join(UPLOAD_FOLDER, f"{file_id}_{filename}")
    sig_path = os.path.join(UPLOAD_FOLDER, f"{file_id}.sig")

    with open(file_path, "wb") as f:
        f.write(data)
    with open(sig_path, "wb") as f:
        f.write(signature)

    files_db[file_id] = {
        "filename": filename,
        "filepath": file_path,
        "sigpath": sig_path,
        "timestamp": os.path.getmtime(file_path)
    }

    return jsonify({"file_id": file_id, "signature": signature_b64})

@app.route("/api/files")
def list_files():
    return jsonify([
        {"file_id": fid, "filename": info["filename"], "timestamp": info["timestamp"]}
        for fid, info in files_db.items()
    ])

@app.route("/download/<file_id>")
def download(file_id):
    info = files_db.get(file_id)
    if not info:
        return "File not found", 404
    return send_file(info["filepath"], as_attachment=True, download_name=info["filename"])

@app.route("/api/verify/<file_id>")
def verify(file_id):
    info = files_db.get(file_id)
    if not info:
        return jsonify({"valid": False}), 404

    with open(info["filepath"], "rb") as f:
        data = f.read()
    with open(info["sigpath"], "rb") as f:
        signature = f.read()

    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return jsonify({"valid": True})
    except (ValueError, TypeError):
        return jsonify({"valid": False})

@app.route("/public_key")
def get_public_key():
    return public_key.export_key().decode()

@app.route("/api/handshake/send", methods=["POST"])
def send_handshake():
    handshake_status["status"] = "hello"
    return jsonify({"status": "hello"})

@app.route("/api/handshake/status")
def check_handshake():
    return jsonify({"status": handshake_status["status"]})

@app.route("/api/handshake/accept", methods=["POST"])
def accept_handshake():
    if handshake_status["status"] == "hello":
        handshake_status["status"] = "ready"
        return jsonify({"status": "ready"})
    return jsonify({"status": handshake_status["status"]})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
