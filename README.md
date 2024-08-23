# YouTube Forensics Tool

### Overview

The **YouTube Forensics Tool** is a desktop application designed for digital forensics professionals to collect and preserve video evidence from YouTube. The tool downloads YouTube videos, generates a SHA-256 hash for the downloaded video file to ensure its integrity, and creates a detailed forensic report suitable for use in your casefile.

### Features

- **YouTube Video Download**: Download videos from YouTube using `yt-dlp`.
- **SHA-256 Hash Generation**: Generate a SHA-256 hash for the downloaded video to verify its integrity.
- **Forensic Report Creation**: Generate a PDF report that includes video metadata, hash value, and other relevant details.
- **User-Friendly Interface**: Simple and intuitive interface built with PyQt6.

### Requirements

- Python 3.x
- PyQt6
- yt-dlp
- hashlib (standard Python library)
- reportlab

### Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/ryd3v/yt-fp.git
   cd yt-fp
   ```

2. **Create and Activate a Virtual Environment**:

   ```bash
   python -m venv venv
   source venv/bin/activate   # On Windows use `venv\Scripts\activate`
   ```

3. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

### Usage

1. **Run the Application**:

   ```bash
   python main.py
   ```

2. **Input YouTube URL**:

   - Paste the YouTube video URL into the provided input field.

3. **Select Download Directory**:

   - Choose the directory where you want to save the downloaded video and the forensic report.

4. **Start Evidence Collection**:

   - Click the "Start Evidence Collection" button to download the video, generate its hash, and create the forensic report.

5. **Review the Report**:
   - The forensic report will be saved as a PDF file in the selected directory, including all relevant details for court use.

### Packaging

To create a standalone executable, use PyInstaller:

```bash
pyinstaller main.spec
```

The executable will be available in the `dist/` directory.

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

### Contributing

Feel free to open issues or submit pull requests. Contributions are welcome!

### Contact

For any inquiries or support, please contact [ryd3v](https://ryd3v.com)
