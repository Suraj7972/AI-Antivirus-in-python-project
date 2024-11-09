import os
import hashlib
import requests
import PySimpleGUI as sg
from PIL import Image, ImageTk

# Replace 'YOUR_API_KEY' with your VirusTotal API key
API_KEY = 'ENTER YOUR API EDIT THIS WITH YOURS'

class VirusScannerApp:
    def __init__(self):
        self.company_name_path = "ADD THE FILE PATH WHERE YOUR LOGO IS"  # Provide the path to your company name image here
        self.logo_path = "logo.jpg"
        bg_image_path = "Virus Scanner.jpg"  # Updated background image path

        self.layout = [
            [sg.Image(key="-BACKGROUND-", filename=os.path.abspath(bg_image_path), size=(800, 600))],
            [sg.Image(key="-COMPANY_NAME-"), sg.Text("Suraj SCANNER", font=("Helvetica", 16), justification='center', text_color="white")],
            [sg.Image(key="-LOGO-", pad=(50, 0))],
            [sg.Text("Where Safety Meets Innovation", font=("Helvetica", 14), text_color="white")],
            [sg.Text("Our Advanced Virus Scanner Empowers You to Explore the Digital Landscape,", font=("Helvetica", 12), text_color="white")],
            [sg.Text("Knowing Our Shield is Always There.", font=("Helvetica", 12), text_color="white")],
            [
                sg.Button("Choose File", key="-UPLOAD-", size=(20, 1), font=("Helvetica", 12)),
                sg.Button("Paste Link", key="-LINK-", size=(20, 1), font=("Helvetica", 12)),
                sg.Button("Scan Specific Drive", key="-DRIVE-", size=(20, 1), font=("Helvetica", 12)),
                sg.Button("Scan Specific File Types", key="-FILE_TYPES-", size=(20, 1), font=("Helvetica", 12))
            ],
            [sg.ProgressBar(100, orientation="h", size=(50, 20), key="-PROGRESS-", bar_color=("#FFD700", "#aa1f2e"))],
            [sg.Text("", key="_OUTPUT_", size=(60, 20), font=("Helvetica", 12), text_color="white")],
            [sg.Button("Clear Output", key="-CLEAR-", size=(20, 1), font=("Helvetica", 12)),
             sg.Button("Exit", key="-EXIT-", size=(20, 1), font=("Helvetica", 12))]
        ]

        self.window = sg.Window(
            "Sarsan Supreme - Virus Scanner",
            self.layout,
            finalize=True
        )
        self.progress_bar = self.window["-PROGRESS-"]
        self.progress_bar_elem = self.progress_bar.Widget
        self.total_files = 0
        self.current_file = 0
        self.load_images()
    def load_images(self):
        # Load the company name image using PIL (Pillow)
        company_name_image = Image.open(self.company_name_path)
        company_name_image.thumbnail((300, 100))  # Resize the image to fit the GUI

        # Create a PySimpleGUI Image object from the company name image
        company_name_byte_array = ImageTk.PhotoImage(company_name_image)
        self.window["-COMPANY_NAME-"].update(data=company_name_byte_array)

        # Load the logo image using PIL (Pillow)
        logo_image = Image.open(self.logo_path)
        logo_image.thumbnail((300, 100))  # Resize the image to fit the GUI

        # Create a new image with the logo and text
        composite_image = Image.new("RGB", (400, 100), (255, 255, 255))  # White background
        composite_image.paste(logo_image, (10, 30))  # Position the logo at (10, 30)

        # Create a PySimpleGUI Image object from the composite image
        img_byte_array = ImageTk.PhotoImage(composite_image)
        self.window["-LOGO-"].update(data=img_byte_array)

    def calculate_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(8192)
                if not data:
                    break
                sha256_hash.update(data)
        return sha256_hash.hexdigest()
        
    def scan_file(self, file_path):
        # The virus scanning logic from the first code
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(8192)
                if not data:
                    break
                sha256_hash.update(data)
        file_hash = sha256_hash.hexdigest()

        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': API_KEY}

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            scan_date = response.json()['data']['attributes']['last_analysis_date']
            last_analysis_stats = response.json()['data']['attributes']['last_analysis_stats']

            total_scans = last_analysis_stats.get('total', 0)
            positives = last_analysis_stats.get('malicious', 0)
            scan_results = response.json()['data']['attributes']['last_analysis_results']

            result_text = f"File: {file_path}\nScan Date: {scan_date}\nTotal Scans: {total_scans}\nPositives: {positives}\nScan Results:\n"
            for engine, result in scan_results.items():
                result_text += f"{engine}: {result['result']} - {result.get('category', 'Unknown')}\n"

            return result_text
        else:
            return "File not found or other error occurred."

    def upload_file(self):
        file_path = sg.popup_get_file("Select a file to scan")
        if file_path:
            result_text = self.scan_file(file_path)
            self.display_results(result_text)
            self.progress_bar_elem["value"] = 100

    def paste_link(self):
        link = sg.popup_get_text("Paste the link to scan:")
        if link:
            # You can implement scanning the link with VirusTotal API here
            result_text = f"Pasting Link: {link}\nPlease wait...\n"
            self.display_results(result_text)
            self.progress_bar_elem["value"] = 100

    def update_progress_bar(self):
        if self.total_files > 0:
            progress_percent = int(self.current_file / self.total_files * 100)
            self.progress_bar_elem["value"] = progress_percent
            self.progress_bar.update()

    def display_results(self, result_text):
        self.window["_OUTPUT_"].update(result_text)

    def scan_specific_file_types(self):
        file_types = sg.popup_get_text("Enter file types to scan (e.g., *.exe, *.docx)", "Scan Specific File Types")
        if file_types:
            files = []
            for root, _, filenames in os.walk(os.path.expanduser("~")):
                for filename in filenames:
                    if filename.endswith(file_types):
                        files.append(os.path.join(root, filename))

            if files:
                self.total_files = len(files)
                self.current_file = 0
                for file_path in files:
                    result_text = self.scan_file(file_path)
                    self.display_results(result_text)
                    self.current_file += 1
                    self.update_progress_bar()
            else:
                sg.popup("No files found with the specified file types.")

    def run(self):
        while True:
            event, values = self.window.read()

            if event == sg.WIN_CLOSED or event == "-EXIT-":
                break
            elif event == "-UPLOAD-":
                self.upload_file()
            elif event == "-LINK-":
                self.paste_link()
            elif event == "-DRIVE-":
                self.select_drive_for_scan()
            elif event == "-FILE_TYPES-":
                self.scan_specific_file_types()
            elif event == "-CLEAR-":
                self.window["_OUTPUT_"].update("")

if __name__ == "__main__":
    app = VirusScannerApp()
    app.run()
