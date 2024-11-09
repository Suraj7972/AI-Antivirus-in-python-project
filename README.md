Advanced AI Virus Scanner

Description:

This desktop application empowers you to scan your system for potential threats by uploading files, scanning entire drives, or pasting links. It leverages the power of the VirusTotal API, which incorporates over 60 antivirus engines, to provide comprehensive scan results.
![Screenshot 2024-11-09 105433](https://github.com/user-attachments/assets/ca07ac3c-18df-4e15-80fa-cb239957be05)


Features:

Upload individual files for scanning.
Scan specific drives for viruses. [*] (Feature not yet implemented)
Paste links for scanning. 
Analyze scan results, including scan date, total scans, positives detected, and detailed results from each antivirus engine used by VirusTotal.
Clear output window to start fresh scans.
![Screenshot 2024-11-09 105144](https://github.com/user-attachments/assets/fa835b89-efd8-4158-a68e-eebc4d507e75)

Installation:

While this is a Python script, users will need to have Python 3 and the PySimpleGUI library installed. You can install PySimpleGUI using pip:

Bash
pip install PySimpleGUI
Use code with caution.

Usage:

Copy and paste the main.py file into your desired directory.
Obtain your own VirusTotal API key: You can create a free API key at https://docs.virustotal.com/docs/api-overview. Replace YOUR_API_KEY in the code with your own key.
Run the application: Open a terminal or command prompt, navigate to the directory containing main.py, and execute the following command:
Bash
python main.py
Use code with caution.

Explanation of Button Functionality:

Upload File: Click this button to browse your system and select a file for scanning.
Scan Drive (Not Yet Implemented): This button will be functional in a future update, allowing you to scan a specific drive for potential threats.
Paste Link : This button is planned for future implementation and will enable you to scan URLs for malicious content.
Clear Output: Use this button to clear the results window and prepare for a new scan.
Requirements:

Python 3 (Specify version if needed)
PySimpleGUI library (pip install PySimpleGUI)
VirusTotal API Key (Replace YOUR_API_KEY with your own key)
Code Structure:

The code is primarily built around the VirusScannerApp class. This class handles the user interface layout, functionalities like uploading files and displaying results, and interacts with the VirusTotal API for threat analysis.

Contributing (Optional):

If you'd like to contribute to this project's development, feel free to reach out and discuss your ideas! We appreciate any contributions that enhance the functionality or user experience.

License:

This project is distributed under the MIT License (refer to the LICENSE file for details).

Author(s):
Suraj Rajendra Gundre

Acknowledgments:

VirusTotal API (https://docs.virustotal.com/docs/api-overview)
PySimpleGUI library (https://docs.pysimplegui.com/en/latest/)
