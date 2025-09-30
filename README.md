```markdown
# 🔍 Forensics CTF Attack Playbook
## Complete Digital Forensics Guide for Kali Linux

> **Philosophy**: In forensics CTFs, data is never truly deleted. The flag is hidden in plain sight, encoded in obscure formats, or buried in metadata.

---

## 📋 Table of Contents
1. [Initial Setup & Tools](#initial-setup)
2. [File Analysis Basics](#1-file-analysis)
3. [Image Forensics](#2-image-forensics)
4. [Audio Forensics](#3-audio-forensics)
5. [Video Forensics](#4-video-forensics)
6. [Memory Forensics](#5-memory-forensics)
7. [Disk & Filesystem Forensics](#6-disk-forensics)
8. [Network Forensics (PCAP)](#7-network-forensics)
9. [PDF & Document Forensics](#8-document-forensics)
10. [Archive & Compression](#9-archive-forensics)
11. [Steganography](#10-steganography)
12. [Malware Analysis](#11-malware-analysis)
13. [Crypto & Encoding](#12-crypto-encoding)

---

## Initial Setup & Tools {#initial-setup}

### Essential Tools Installation
```bash
# Update system first
sudo apt update && sudo apt upgrade -y

# File analysis tools
sudo apt install -y file binwalk foremost hexedit xxd strings

# Image forensics
sudo apt install -y exiftool steghide stegsolve zsteg outguess
pip3 install stegcracker pillow

# Audio/Video
sudo apt install -y audacity sox ffmpeg mediainfo

# Memory forensics
pip3 install volatility3
git clone https://github.com/volatilityfoundation/volatility.git  

# Disk forensics
sudo apt install -y sleuthkit autopsy testdisk photorec

# Network forensics
sudo apt install -y wireshark tshark tcpdump ngrep
sudo apt install -y networkminer

# PDF analysis
sudo apt install -y pdfid pdf-parser qpdf pdftk

# Archive tools
sudo apt install -y p7zip-full unrar-free

# Steganography
sudo apt install -y steghide stegsnow
git clone https://github.com/zardus/ctf-tools  
cd ctf-tools && bin/manage-tools setup stegsolve

# Misc tools
sudo apt install -y ghex bless okteta gimp
pip3 install pycryptodome

# Advanced tools
cargo install ripgrep fd-find
pip3 install binwalk
```

### Workspace Setup
```bash
# Create organized workspace
mkdir -p ~/forensics/{evidence,extracted,tools,notes,solved}
cd ~/forensics/evidence

# Set up aliases for quick access
cat >> ~/.bashrc << 'EOF'
alias fcd='cd ~/forensics/evidence'
alias strings-all='strings -a -n 8'
alias hexdump-pretty='hexdump -C'
alias file-deep='file -b --mime-type'
EOF

source ~/.bashrc
```

---

## 1. File Analysis Basics {#1-file-analysis}

### Step 1.1: Identify File Type
```bash
# Basic file identification
file suspicious.bin

# Get MIME type
file -b --mime-type suspicious.bin

# Detailed file info
file -z suspicious.bin  # Look inside compressed files

# Magic bytes identification
xxd suspicious.bin | head -n 5

# Alternative: hexdump
hexdump -C suspicious.bin | head -n 20
```

### Common Magic Bytes Reference
```
PNG:  89 50 4E 47 0D 0A 1A 0A
JPEG: FF D8 FF
GIF:  47 49 46 38
ZIP:  50 4B 03 04
PDF:  25 50 44 46
ELF:  7F 45 4C 46
```

### Step 1.2: Extract Strings
```bash
# Extract ASCII strings (min 8 chars)
strings suspicious.bin > strings_output.txt

# Extract all printable strings
strings -a suspicious.bin

# Extract with offsets
strings -t x suspicious.bin

# Unicode strings
strings -e l suspicious.bin  # Little-endian
strings -e b suspicious.bin  # Big-endian

# Search for specific patterns
strings suspicious.bin | grep -i "flag\|password\|key"
strings suspicious.bin | grep -E "[A-Za-z0-9+/]{20,}="  # Base64

# Extract with minimum length
strings -n 4 suspicious.bin
```

### Step 1.3: Binwalk Analysis
```bash
# Scan for embedded files
binwalk suspicious.bin

# Extract all embedded files
binwalk -e suspicious.bin

# Extract with specific signature
binwalk -D 'png image:png' suspicious.bin

# Recursive extraction (dangerous, use carefully)
binwalk -Me suspicious.bin

# Entropy analysis (detect encryption/compression)
binwalk -E suspicious.bin
```

### Step 1.4: Foremost File Carving
```bash
# Recover deleted files
foremost -i disk.img -o recovered/

# Specify file types
foremost -t jpg,png,pdf -i disk.img -o output/

# With configuration file
foremost -c /etc/foremost.conf -i disk.img -o output/
```

### Step 1.5: Manual Hex Analysis
```bash
# Hex editor (interactive)
hexedit suspicious.bin

# Display hex dump
xxd suspicious.bin > hex_dump.txt

# Reverse hex dump to binary
xxd -r hex_dump.txt > recovered.bin

# Show only hex values
xxd -p suspicious.bin

# Compare two files
cmp -l file1.bin file2.bin | gawk '{printf "%08X %02X %02X\n", $1-1, strtonum(0$2), strtonum(0$3)}'
```

---

## 2. Image Forensics {#2-image-forensics}

### Step 2.1: Metadata Extraction
```bash
# ExifTool (best for metadata)
exiftool image.jpg

# Extract all metadata to text
exiftool -a -G1 image.jpg > metadata.txt

# Search for GPS coordinates
exiftool -gps:all image.jpg

# Extract thumbnail
exiftool -b -ThumbnailImage image.jpg > thumb.jpg

# Batch process
exiftool -r /path/to/images/ > all_metadata.txt

# Remove metadata
exiftool -all= image.jpg
```

### Step 2.2: Visual Analysis
```bash
# Open in image viewer with zoom
eog image.jpg

# Open in GIMP for advanced editing
gimp image.jpg
# In GIMP: Filters → Enhance → Sharpen/Unsharp Mask
# Colors → Curves/Levels → Adjust to reveal hidden data
```

### Step 2.3: Steghide (JPEG/BMP/WAV/AU)
```bash
# Check if steghide was used
steghide info image.jpg

# Extract hidden data (with password)
steghide extract -sf image.jpg -p password

# Extract without password
steghide extract -sf image.jpg

# Brute force password
stegcracker image.jpg /usr/share/wordlists/rockyou.txt

# Embed data (for testing)
steghide embed -cf image.jpg -ef secret.txt -p password
```

### Step 2.4: Zsteg (PNG/BMP)
```bash
# Analyze LSB (Least Significant Bit)
zsteg image.png

# All possible extractions
zsteg -a image.png

# Specific bit plane
zsteg -E "b1,rgb,lsb" image.png

# Save extracted data
zsteg -E "b1,r,lsb,xy" image.png > extracted.txt
```

### Step 2.5: StegSolve
```bash
# Start StegSolve (GUI)
java -jar ~/tools/stegsolve.jar

# Steps in GUI:
# 1. Open image
# 2. Analyse → Frame Browser (for GIF animations)
# 3. Analyse → Data Extract
#    - Select bit planes (Red/Green/Blue 0-7)
#    - Try different combinations
# 4. Analyse → Stereogram Solver (for 3D images)
# 5. File → Save Bin (save extracted data)
```

### Step 2.6: Outguess
```bash
# Extract hidden data
outguess -r image.jpg output.txt

# With key
outguess -k "password" -r image.jpg output.txt

# Statistical analysis
outguess -s -r image.jpg
```

### Step 2.7: Image Manipulation Detection
```bash
# Error Level Analysis (ELA)
convert image.jpg -quality 95 ela.jpg
composite image.jpg ela.jpg -compose difference ela_result.png

# Clone detection
python3 ~/tools/image-forensics/clone_detection.py image.jpg

# Noise analysis
convert image.jpg -median 3 noise_analysis.jpg
```

### Step 2.8: QR Codes & Barcodes
```bash
# Install zbar
sudo apt install -y zbar-tools

# Decode QR code
zbarimg image.png

# From webcam
zbarcam

# Online alternative: https://zxing.org/w/decode.jspx  
```

### Step 2.9: Pixel Value Analysis
```python
# pixel_analysis.py
from PIL import Image
import numpy as np

img = Image.open('image.png')
pixels = np.array(img)

# Extract LSB from each channel
r_lsb = pixels[:,:,0] & 1
g_lsb = pixels[:,:,1] & 1
b_lsb = pixels[:,:,2] & 1

# Save LSB as image
Image.fromarray(r_lsb.astype(np.uint8) * 255).save('red_lsb.png')
Image.fromarray(g_lsb.astype(np.uint8) * 255).save('green_lsb.png')
Image.fromarray(b_lsb.astype(np.uint8) * 255).save('blue_lsb.png')

# Extract text from LSB
def extract_lsb_text(img_path):
    img = Image.open(img_path)
    pixels = np.array(img)
    
    binary = ''
    for row in pixels:
        for pixel in row:
            binary += str(pixel[0] & 1)  # Red channel LSB
    
    # Convert binary to ASCII
    text = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) == 8:
            text += chr(int(byte, 2))
    
    return text

print(extract_lsb_text('image.png'))
```

---

## 3. Audio Forensics {#3-audio-forensics}

### Step 3.1: Audio Metadata
```bash
# Get audio info
mediainfo audio.mp3
exiftool audio.wav

# Detailed format info
soxi audio.wav
ffprobe audio.mp3
```

### Step 3.2: Spectral Analysis
```bash
# Open in Audacity
audacity audio.wav

# In Audacity:
# 1. Select audio
# 2. Analyze → Plot Spectrum
# 3. Change to Spectrogram view: Track dropdown → Spectrogram
# 4. Look for hidden messages in frequency domain

# Command-line spectrogram
sox audio.wav -n spectrogram -o spectrogram.png

# High resolution spectrogram
sox audio.wav -n spectrogram -x 3000 -y 513 -z 120 -w Kaiser -o spec_hq.png
```

### Step 3.3: Steghide on Audio
```bash
# Extract from WAV/AU
steghide info audio.wav
steghide extract -sf audio.wav

# Brute force
stegcracker audio.wav /usr/share/wordlists/rockyou.txt
```

### Step 3.4: LSB in Audio
```bash
# Extract LSB data
python3 audio_lsb_extract.py audio.wav

# Detect hidden data in audio
detect-steg audio.wav
```

```python
# audio_lsb_extract.py
import wave

def extract_lsb(wav_file):
    audio = wave.open(wav_file, mode='rb')
    frames = bytearray(list(audio.readframes(audio.getnframes())))
    
    extracted = [frame & 1 for frame in frames]
    
    # Convert bits to bytes
    string = ""
    for i in range(0, len(extracted), 8):
        byte = extracted[i:i+8]
        if len(byte) == 8:
            string += chr(int(''.join([str(bit) for bit in byte]), 2))
    
    audio.close()
    return string

print(extract_lsb('audio.wav'))
```

### Step 3.5: DTMF Tone Detection
```bash
# Install multimon-ng
sudo apt install -y multimon-ng

# Decode DTMF tones
multimon-ng -t wav -a DTMF audio.wav

# Alternative: use online tool
# https://unframework.github.io/dtmf-detect/  
```

### Step 3.6: Morse Code Detection
```bash
# Visual morse code in spectrogram
audacity audio.wav

# Decode morse code (if audio is beeps)
# Use online decoder: https://morsecode.world/international/decoder/audio-decoder-adaptive.html  
```

### Step 3.7: Reverse/Speed Manipulation
```bash
# Reverse audio
sox audio.wav reversed.wav reverse

# Change speed (2x faster)
sox audio.wav faster.wav speed 2.0

# Change pitch
sox audio.wav pitched.wav pitch 500

# Slow down without changing pitch
sox audio.wav slow.wav tempo 0.5
```

---

## 4. Video Forensics {#4-video-forensics}

### Step 4.1: Video Metadata
```bash
# Comprehensive metadata
mediainfo video.mp4
exiftool video.mp4

# FFmpeg probe
ffprobe -v quiet -print_format json -show_format -show_streams video.mp4

# Extract creation date
exiftool -CreateDate video.mp4
```

### Step 4.2: Extract Frames
```bash
# Extract all frames as images
ffmpeg -i video.mp4 frames/frame_%04d.png

# Extract 1 frame per second
ffmpeg -i video.mp4 -vf fps=1 frames/frame_%04d.png

# Extract specific frame (at 10 seconds)
ffmpeg -ss 00:00:10 -i video.mp4 -frames:v 1 frame_10s.png

# Extract only I-frames (keyframes)
ffmpeg -i video.mp4 -vf "select='eq(pict_type,I)'" -vsync 0 keyframes/frame_%04d.png
```

### Step 4.3: Extract Audio Track
```bash
# Extract audio
ffmpeg -i video.mp4 -vn -acodec copy audio.aac

# Convert to WAV for analysis
ffmpeg -i video.mp4 -vn audio.wav
```

### Step 4.4: Analyze Subtitles
```bash
# Extract subtitles
ffmpeg -i video.mp4 -map 0:s:0 subtitles.srt

# View embedded subtitles
exiftool video.mp4 | grep -i subtitle

# Extract all text tracks
ffprobe video.mp4 -show_streams -select_streams s
```

### Step 4.5: Frame-by-Frame Analysis
```bash
# Use VLC for frame-by-frame
vlc video.mp4
# Press 'E' to go frame-by-frame

# Use ffplay
ffplay -i video.mp4

# Extract specific suspicious frames
ffmpeg -i video.mp4 -vf "select='between(n,100,200)'" -vsync 0 suspicious_frames/frame_%04d.png
```

### Step 4.6: Check for Hidden Data in Video Container
```bash
# Binwalk on video file
binwalk video.mp4
binwalk -e video.mp4

# Look for appended data
tail -c 10000 video.mp4 | strings

# Compare file size vs actual video size
mediainfo video.mp4 | grep "File size"
ffprobe video.mp4 2>&1 | grep Duration
```

---

## 5. Memory Forensics {#5-memory-forensics}

### Step 5.1: Memory Dump Analysis with Volatility 3
```bash
# Identify OS profile
python3 vol.py -f memory.dmp windows.info
python3 vol.py -f memory.dmp linux.info

# List processes
python3 vol.py -f memory.dmp windows.pslist
python3 vol.py -f memory.dmp windows.pstree

# List network connections
python3 vol.py -f memory.dmp windows.netscan

# Dump process memory
python3 vol.py -f memory.dmp -o dump/ windows.memmap --pid 1234 --dump

# List command history
python3 vol.py -f memory.dmp windows.cmdline

# Extract files
python3 vol.py -f memory.dmp windows.filescan
python3 vol.py -f memory.dmp -o extracted/ windows.dumpfiles --pid 1234

# Registry analysis
python3 vol.py -f memory.dmp windows.registry.hivelist
python3 vol.py -f memory.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Malware detection
python3 vol.py -f memory.dmp windows.malfind

# DLL list
python3 vol.py -f memory.dmp windows.dlllist --pid 1234
```

### Step 5.2: Volatility 2 (Legacy)
```bash
# Determine profile
python2 vol.py -f memory.dmp imageinfo

# With determined profile
python2 vol.py -f memory.dmp --profile=Win7SP1x64 pslist

# Common plugins
python2 vol.py -f memory.dmp --profile=Win7SP1x64 hivelist
python2 vol.py -f memory.dmp --profile=Win7SP1x64 hashdump
python2 vol.py -f memory.dmp --profile=Win7SP1x64 clipboard
python2 vol.py -f memory.dmp --profile=Win7SP1x64 screenshot --dump-dir=./
```

### Step 5.3: String Analysis in Memory
```bash
# Extract strings from memory dump
strings memory.dmp > strings.txt
strings -e l memory.dmp > strings_unicode.txt

# Search for flags
grep -i "flag\|password\|key" strings.txt

# Search for URLs
grep -E "https?://" strings.txt

# Search for file paths
grep -E "[A-Z]:\\\\" strings.txt

# Search for email addresses
grep -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" strings.txt
```

### Step 5.4: Bulk Extractor
```bash
# Extract artifacts from memory
bulk_extractor -o output memory.dmp

# Check extracted data
ls output/
cat output/url.txt
cat output/email.txt
cat output/domain.txt
cat output/ip.txt
```

---

## 6. Disk & Filesystem Forensics {#6-disk-forensics}

### Step 6.1: Disk Image Analysis
```bash
# Get disk info
fdisk -l disk.img
mmls disk.img

# Calculate partition offset
# If partition starts at sector 2048 and sector size is 512:
# Offset = 2048 * 512 = 1048576

# Mount disk image
sudo mkdir /mnt/forensics
sudo mount -o loop,ro,offset=1048576 disk.img /mnt/forensics

# For multiple partitions
sudo losetup -fP disk.img
lsblk  # Find loop device
sudo mount -o ro /dev/loop0p1 /mnt/forensics
```

### Step 6.2: File System Analysis with Sleuth Kit
```bash
# List partition layout
mmls disk.img

# File system stats
fsstat -o 2048 disk.img

# List files and directories
fls -r -o 2048 disk.img

# Display file content
icat -o 2048 disk.img 12345 > recovered_file.txt

# Display file metadata
istat -o 2048 disk.img 12345

# Timeline creation
fls -r -m / -o 2048 disk.img > timeline.body
mactime -b timeline.body -d > timeline.csv
```

### Step 6.3: Deleted File Recovery
```bash
# PhotoRec (powerful file carver)
photorec disk.img

# In interactive mode:
# 1. Select partition
# 2. Select file types to recover
# 3. Choose destination

# TestDisk (partition recovery)
testdisk disk.img
```

### Step 6.4: Autopsy (GUI)
```bash
# Start Autopsy
autopsy

# Web interface will open
# Create new case → Add disk image → Run ingest modules
# Key modules:
# - Recent Activity
# - Hash Lookup
# - Keyword Search
# - File Type Identification
```

### Step 6.5: Registry Analysis (Windows)
```bash
# Extract registry hives from disk
icat -o 2048 disk.img <inode> > SAM
icat -o 2048 disk.img <inode> > SYSTEM

# Parse with reglookup
reglookup SAM

# Extract password hashes
samdump2 SYSTEM SAM

# Registry viewer (GUI)
sudo apt install -y regripper
rip.pl -r SAM -p samparse
```

---

## 7. Network Forensics (PCAP) {#7-network-forensics}

### Step 7.1: Initial PCAP Analysis
```bash
# Basic info
capinfos capture.pcap

# Quick statistics
tshark -r capture.pcap -qz io,phs

# Protocol hierarchy
tshark -r capture.pcap -qz io,stat,0
```

### Step 7.2: Wireshark Analysis
```bash
# Open in Wireshark
wireshark capture.pcap &

# Common display filters:
http                    # HTTP traffic
http.request            # HTTP requests only
http.request.method == "POST"
ftp                     # FTP traffic
ftp-data                # FTP data transfer
tcp.stream eq 0         # Follow TCP stream 0
ip.addr == 192.168.1.1  # Specific IP
tcp.port == 80          # Specific port
tcp contains "flag"     # Contains string
dns                     # DNS queries
```

### Step 7.3: Extract Objects from PCAP
```bash
# In Wireshark: File → Export Objects → HTTP/SMB/TFTP

# Command line (HTTP)
tshark -r capture.pcap --export-objects http,extracted/

# Extract FTP data
tshark -r capture.pcap -Y "ftp-data" -T fields -e ftp-data.data | xxd -r -p > file.bin

# Extract files with foremost
foremost -t all -i capture.pcap -o extracted/
```

### Step 7.4: Follow TCP/HTTP Streams
```bash
# Follow specific TCP stream
tshark -r capture.pcap -z follow,tcp,ascii,0 > stream_0.txt

# Follow all TCP streams
for i in {0..100}; do
    tshark -r capture.pcap -z follow,tcp,ascii,$i > stream_$i.txt 2>/dev/null
done

# Extract HTTP objects
tshark -r capture.pcap -Y "http.request or http.response" -T fields \
  -e frame.number -e http.request.full_uri -e http.file_data > http_data.txt
```

### Step 7.5: Analyze DNS Traffic
```bash
# Extract DNS queries
tshark -r capture.pcap -Y "dns.qry.type == 1" -T fields -e dns.qry.name

# Look for DNS tunneling
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# DNS exfiltration detection (long domain names)
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | \
  awk 'length > 50'
```

### Step 7.6: Extract Credentials
```bash
# HTTP Basic Auth
tshark -r capture.pcap -Y "http.authbasic" -T fields -e http.authbasic

# FTP credentials
tshark -r capture.pcap -Y "ftp.request.command == USER or ftp.request.command == PASS" \
  -T fields -e ftp.request.arg

# SMTP credentials
tshark -r capture.pcap -Y "smtp.req.parameter" -T fields -e smtp.req.parameter
```

### Step 7.7: Network Miner (GUI)
```bash
# Install and run
sudo apt install -y networkminer
sudo networkminer

# Features:
# - Automatic file extraction
# - Credential detection
# - Host information
# - Session reconstruction
```

### Step 7.8: Search for Patterns
```bash
# Search for flags in packets
tshark -r capture.pcap -Y 'frame contains "flag"' -x

# Search for email addresses
tshark -r capture.pcap -T fields -e text | grep -Eo "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

# Search for credit cards
tshark -r capture.pcap -T fields -e text | grep -Eo "[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}"

# Search for IP addresses
tshark -r capture.pcap -T fields -e ip.src -e ip.dst | sort | uniq
```

---

## 8. PDF & Document Forensics {#8-document-forensics}

### Step 8.1: PDF Metadata Analysis
```bash
# Extract metadata
exiftool document.pdf

# PDF structure analysis
pdfinfo document.pdf

# Detailed PDF info
pdfid.py document.pdf

# Check for JavaScript
pdf-parser.py -s javascript document.pdf

# Extract streams
pdf-parser.py -a document.pdf > pdf_analysis.txt
```

### Step 8.2: Extract Embedded Files
```bash
# List embedded files
pdfdetach -list document.pdf

# Extract all attachments
pdfdetach -saveall document.pdf -o extracted/

# Extract images
pdfimages document.pdf images/img

# Extract text
pdftotext document.pdf output.txt

# Extract fonts
pdffonts document.pdf
```

### Step 8.3: Analyze PDF Structure
```bash
# Decompress PDF streams
qpdf --qdf --object-streams=disable document.pdf uncompressed.pdf

# Now analyze with text editor
cat uncompressed.pdf | grep -i "flag\|password"

# Search for hidden objects
pdf-parser.py --search "/EmbeddedFile" document.pdf

# Extract specific object
pdf-parser.py --object 10 --raw document.pdf > object_10.bin
```

### Step 8.4: Office Document Analysis
```bash
# Extract metadata from Office docs
exiftool document.docx

# Unzip Office document (docx is a zip file)
unzip document.docx -d extracted_docx/

# Check for macros
olevba document.doc
olevba document.docm

# Extract VBA macros
olevba -c document.doc

# Analyze embedded objects
oleid document.doc
```

### Step 8.5: LibreOffice/OpenOffice
```bash
# Extract (also a zip file)
unzip document.odt -d extracted_odt/

# Check content.xml
cat extracted_odt/content.xml | xmllint --format -

# Extract images
unzip -j document.odt "Pictures/*" -d images/
```

---

## 9. Archive & Compression Forensics {#9-archive-forensics}

### Step 9.1: ZIP Analysis
```bash
# List contents
unzip -l archive.zip

# Test integrity
unzip -t archive.zip

# Extract
unzip archive.zip -d extracted/

# Password protected ZIP
# Brute force with fcrackzip
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt archive.zip

# Or use John the Ripper
zip2john archive.zip > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Check for hidden files (after extraction)
ls -la extracted/

# Look for alternate data streams
7z l -slt archive.zip
```

### Step 9.2: RAR Analysis
```bash
# Extract RAR
unrar x archive.rar

# List contents
unrar l archive.rar

# Test
unrar t archive.rar

# Crack password
rarcrack archive.rar --type rar

# Or with John
rar2john archive.rar > hash.txt
john hash.txt
```

### Step 9.3: 7z and Other Formats
```bash
# Extract 7z
7z x archive.7z

# List with details
7z l -slt archive.7z

# Crack 7z password
7z2john archive.7z > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Step 9.4: Tar Archives
```bash
# Extract tar.gz
tar -xzf archive.tar.gz

# Extract tar.bz2
tar -xjf archive.tar.bz2

# List contents
tar -tzf archive.tar.gz

# Extract specific file
tar -xzf archive.tar.gz path/to/file
```

### Step 9.5: Hidden Data in Archives
```bash
# Check for data after ZIP end marker
binwalk archive.zip

# Extract appended data
dd if=archive.zip bs=1 skip=<offset> of=hidden_data.bin

# Check file size vs content size
ls -lh archive.zip
unzip -l archive.zip | tail -1
```

---

## 10. Steganography {#10-steganography}

### Step 10.1: Image Steganography Tools Matrix

```bash
# Quick test all common tools
steg-test.sh image.jpg

# StegCracker (brute force steghide)
stegcracker image.jpg /usr/share/wordlists/rockyou.txt

# Zsteg (PNG/BMP automated)
zsteg -a image.png

# StegSeek (faster steghide cracker)
stegseek image.jpg /usr/share/wordlists/rockyou.txt
```

### Step 10.2: Text Steganography
```bash
# Snow (whitespace steganography)
stegsnow -C hidden_message.txt

# Extract
stegsnow -C hidden_message.txt -p password

# Check for zero-width characters
cat suspicious.txt | od -c | grep -E "\\0"
```

### Step 10.3: Advanced Steganography
```bash
# F5 algorithm (JPEG)
java -jar f5.jar x -p password -e output.txt stego.jpg

# OpenStego
openstego extract -sf stego.png -xf password -kf keyfile.key
```

### Step 10.4: Frequency Domain Steganography
```bash
# FFT analysis (using Python)
python3 fft_stego.py image.png

# Jsteg (JPEG)
jsteg hide cover.jpg secret.txt stego.jpg
jsteg show stego.jpg

# Outguess-ng
outguess-ng -r stego.jpg extracted.txt
```

### Step 10.5: Custom LSB Extraction
```python
# lsb_extractor.py
def extract_lsb_custom(image_path, channels='RGB', bit_planes=[0]):
    from PIL import Image
    import numpy as np
    
    img = Image.open(image_path)
    pixels = np.array(img)
    
    extracted_bits = ''
    
    for plane in bit_planes:
        for y in range(pixels.shape[0]):
            for x in range(pixels.shape[1]):
                for c_idx, c in enumerate(channels):
                    if c_idx < pixels.shape[2]: # Check if channel exists (e.g., no alpha in RGB)
                        pixel_val = pixels[y, x, c_idx]
                        extracted_bits += str((pixel_val >> plane) & 1)
    
    # Convert bits to text
    text = ''
    for i in range(0, len(extracted_bits), 8):
        byte = extracted_bits[i:i+8]
        if len(byte) == 8:
            char_code = int(byte, 2)
            if 32 <= char_code <= 126 or char_code in [9, 10, 13]: # Printable ASCII + tab, newline, carriage return
                text += chr(char_code)
            else:
                break # Stop if non-printable character found (likely end of message)
    
    return text

# Example usage
message = extract_lsb_custom('image.png', channels='RGB', bit_planes=[0])
print("Extracted message:", message)
```

---

## 11. Malware Analysis {#11-malware-analysis}

### Step 11.1: Static Analysis
```bash
# Basic file info
file suspicious.exe
strings suspicious.exe | grep -i "http\|ftp\|cmd\|powershell\|download\|execute"
hexdump -C suspicious.exe | head -n 50

# PE file analysis (Windows)
exiftool suspicious.exe
pecheck suspicious.exe # From yara-rules project

# Check for packers
peid suspicious.exe # Requires PEiD database
diec suspicious.exe # Detect It Easy

# YARA scan
yara -r /path/to/yara/rules/ suspicious.exe
```

### Step 11.2: Basic Dynamic Analysis (Sandbox)
```bash
# Cuckoo Sandbox (requires setup)
# https://cuckoosandbox.org/

# Basic process monitoring (Linux)
strace -f -o trace.log ./suspicious_binary
grep -i "open\|read\|write\|connect\|socket" trace.log

# Network monitoring
sudo tcpdump -i any -w network_capture.pcap -f "host 192.168.1.100" # Replace with your IP
# Run malware in background, then stop tcpdump
sudo killall tcpdump
```

### Step 11.3: Reverse Engineering (Disassembly)
```bash
# Using objdump (Linux)
objdump -d suspicious_binary > disassembly.txt
objdump -R suspicious_binary # Show imports

# Using Ghidra (GUI, powerful)
# Download from https://ghidra-sre.org/
# Import file, analyze, look for main function, strings, cross-references

# Using Radare2 (CLI)
r2 suspicious_binary
[0x00000000]> aaa # Analyze all
[0x00000000]> pdf # Disassemble function at current address
[0x00000000]> iz # List strings
[0x00000000]> q # Quit
```

### Step 11.4: Python Malware Analysis
```python
# For Python-based malware
uncompyle6 malware.pyc # De-compile .pyc
pyinstxtractor malware.exe # Extract PyInstaller executables
# Then analyze the extracted .py files
```

---

## 12. Crypto & Encoding {#12-crypto-encoding}

### Step 12.1: Common Encoding Detection
```bash
# Base64 detection
echo "SGVsbG8gV29ybGQ=" | base64 -d

# Base32
echo "JBSWY3DPEHPK3PXP" | base32 -d

# Hex string to ASCII
echo "48656c6c6f20576f726c64" | xxd -r -p

# URL encoding
python3 -c "import urllib.parse; print(urllib.parse.unquote('Hello%20World'))"

# Morse Code (if text-based)
python3 morse_decode.py ".... . .-.. .-.. ---"
```

### Step 12.2: Automated Crypto Tools
```bash
# CyberChef (Online)
# https://gchq.github.io/CyberChef/
# Paste encoded text, use "Magic" recipe for auto-detection

# Hash identification
hash-identifier

# Ciphey (auto-decrypt)
pip3 install ciphey
ciphey -t "Encoded text here"

# Hashcat for hash cracking
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt # MD5
hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt # NTLM
```

### Step 12.3: Frequency Analysis
```bash
# For substitution ciphers
python3 freq_analysis.py encrypted.txt

# Online tools like:
# - https://www.boxentriq.com/code-breaking/cipher-identifier
# - https://www.dcode.fr/frequency-analysis
```

```python
# freq_analysis.py
def analyze_frequency(text):
    text = text.upper()
    freq = {}
    total = 0
    for char in text:
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
            total += 1
    
    for char in freq:
        freq[char] = (freq[char] / total) * 100
    
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    print("Letter Frequencies:")
    for char, freq in sorted_freq:
        print(f"{char}: {freq:.2f}%")

# Example usage
with open("encrypted.txt", "r") as f:
    analyze_frequency(f.read())
```

### Step 12.4: Common Ciphers
```bash
# ROT13
echo "Uryyb Jbeyq" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Caesar Cipher (brute force all shifts)
for i in {1..25}; do
    echo "Encrypted text" | tr A-Za-z $(printf %s $(seq -s '' $((26-$i)) 25) $(seq -s '' 0 $((25-$i))))
done

# Vigenère Cipher
# Use CyberChef or dedicated tools like:
# - https://www.dcode.fr/vigenere-cipher
# - vigenere-crack (if available)
```

### Step 12.5: Hash Analysis
```bash
# Identify hash type
hash-identifier

# Crack common hashes with hashcat
# Find mode numbers at: https://hashcat.net/wiki/doku.php?id=example_hashes
# Example: MD5 (mode 0), SHA1 (mode 100), etc.
hashcat -m <mode_number> -a 0 hash.txt /usr/share/wordlists/rockyou.txt

# Or with John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

---

## 🎯 Final Tips & Tricks

1.  **Always start with `file` and `strings`**: These give you the most basic understanding of the data.
2.  **Look for magic bytes**: They reveal the true file type, even if the extension is wrong.
3.  **Metadata is gold**: `exiftool` often reveals crucial information.
4.  **Think outside the box**: The flag might be in a less obvious place (e.g., LSB of alpha channel, appended after file end, in a stream name in a PDF).
5.  **Use online tools**: Sometimes a quick web-based decoder is faster than local tools (e.g., CyberChef, ZXing, Morse decoders).
6.  **Automate common tasks**: Write small scripts for repetitive checks.
7.  **Keep notes**: Document your process, especially for complex challenges.
8.  **Practice**: Use platforms like [OverTheWire](https://overthewire.org/), [CTFtime](https://ctftime.org/), or [TryHackMe](https://tryhackme.com/) to get hands-on experience.

Good luck! 🍀

```
