import sys
import os
import hashlib
import yt_dlp
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QFileDialog, QTextEdit, QMessageBox
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

class YTForensicsApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("YouTube Forensics Tool")
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()

        # YouTube URL Input
        self.url_label = QLabel("YouTube Video URL:")
        self.url_input = QLineEdit()
        layout.addWidget(self.url_label)
        layout.addWidget(self.url_input)

        # Directory Selector
        self.dir_button = QPushButton("Select Download Directory")
        self.dir_button.clicked.connect(self.select_directory)
        layout.addWidget(self.dir_button)

        # Start Button
        self.start_button = QPushButton("Start Evidence Collection")
        self.start_button.clicked.connect(self.start_collection)
        layout.addWidget(self.start_button)

        # Status Display
        self.status_display = QTextEdit()
        self.status_display.setReadOnly(True)
        self.status_display.setPlaceholderText("Status updates will appear here...")
        layout.addWidget(self.status_display)

        self.setLayout(layout)

    def select_directory(self):
        dir_name = QFileDialog.getExistingDirectory(self, "Select Directory")
        if dir_name:
            self.download_directory = dir_name
            self.status_display.append(f"Selected Directory: {dir_name}")

    def is_valid_youtube_url(self, url):
        """Basic validation for YouTube URLs."""
        return url.startswith("https://www.youtube.com/watch?v=") or url.startswith("https://youtu.be/")

    def download_video(self, url, download_path):
        ydl_opts = {
            'outtmpl': os.path.join(download_path, '%(title)s.%(ext)s'),
            'format': 'best',
        }
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info_dict = ydl.extract_info(url, download=True)
            video_path = ydl.prepare_filename(info_dict)
        return video_path

    def generate_hash(self, file_path, algorithm='sha256'):
        if algorithm == 'sha256':
            hash_func = hashlib.sha256()
        elif algorithm == 'md5':
            hash_func = hashlib.md5()
        elif algorithm == 'sha1':
            hash_func = hashlib.sha1()
        else:
            raise ValueError("Unsupported hash algorithm")

        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                hash_func.update(byte_block)
        return hash_func.hexdigest()

    def create_pdf_report(self, evidence_data, report_path):
        c = canvas.Canvas(report_path, pagesize=letter)
        c.drawString(100, 750, "YouTube Forensics Report")
        c.drawString(100, 730, f"Video URL: {evidence_data['url']}")
        c.drawString(100, 710, f"Video Path: {evidence_data['video_path']}")
        c.drawString(100, 690, f"SHA-256 Hash: {evidence_data['hash']}")
        c.drawString(100, 670, f"MD5 Hash: {evidence_data.get('md5_hash', 'N/A')}")
        c.drawString(100, 650, f"SHA-1 Hash: {evidence_data.get('sha1_hash', 'N/A')}")
        c.save()

    def start_collection(self):
        url = self.url_input.text()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a YouTube URL.")
            return
        if not self.is_valid_youtube_url(url):
            QMessageBox.warning(self, "Input Error", "Please enter a valid YouTube URL.")
            return
        if not hasattr(self, 'download_directory'):
            QMessageBox.warning(self, "Input Error", "Please select a download directory.")
            return

        self.status_display.append("Starting evidence collection...")
        self.status_display.append(f"Processing URL: {url}")

        try:
            video_path = self.download_video(url, self.download_directory)
            self.status_display.append(f"Video downloaded: {video_path}")
        except Exception as e:
            QMessageBox.critical(self, "Download Error", f"Failed to download video: {e}")
            return

        self.status_display.append("Generating hashes...")
        video_hash_sha256 = self.generate_hash(video_path, 'sha256')
        video_hash_md5 = self.generate_hash(video_path, 'md5')
        video_hash_sha1 = self.generate_hash(video_path, 'sha1')
        self.status_display.append(f"SHA-256 Hash: {video_hash_sha256}")
        self.status_display.append(f"MD5 Hash: {video_hash_md5}")
        self.status_display.append(f"SHA-1 Hash: {video_hash_sha1}")

        self.status_display.append("Creating report...")
        report_path = os.path.join(self.download_directory, "evidence_report.pdf")
        self.create_pdf_report({
            "url": url,
            "video_path": video_path,
            "hash": video_hash_sha256,
            "md5_hash": video_hash_md5,
            "sha1_hash": video_hash_sha1
        }, report_path)
        self.status_display.append(f"Report created: {report_path}")

        self.status_display.append("Evidence collection completed successfully!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = YTForensicsApp()
    window.show()
    sys.exit(app.exec())
