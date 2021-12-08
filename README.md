# Introduction to CobaltStrikePars3
Welcome to the user manual. 
This document provides the instruction on how you can make use of CobaltStrikePars3 plugin in your Volatility3

## How to run the Plugin
#### 1. Ensure that [Volatility3](https://github.com/volatilityfoundation/volatility3 "Volatility3") has been properly installed on your device
#### 2. Download [CobaltStrikePars3](https://github.com/LimWeiKai/ICT-2202-Team-YH-/blob/gh-pages/CobaltStrikePars3.py "CobaltstrikePars3")
#### 3. Place CobaltStrikePars3 in Volatility3's windows plugins directory
```bash
    volatility3/plugins/windows/
```
#### 4. Run the plugin 
```bash
    python3 vol.py -f [Memory Capture File] windows.CobaltStrikePars3.CSParse
```

Click [here](https://youtu.be/YGkqhZDCVC8) for the demo video. 

Enjoy!

## Contributors
| Name         | Email                 |
|------------- | --------------------- |
| Marven Lim   | 2001357@sit.singaporetech.edu.sg |
| Lim Wei Kai | 2001112@sit.singaporetech.edu.sg |
| Teng Yan Hao | 2003002@sit.singaporetech.edu.sg |
| Jubilian Ho | 2000810@sit.singaporetech.edu.sg |

# License and Copyright Information
Repository content (Excluding third-party resources, see below) shall be released under the [MIT License](LICENSE).
<br /><br />
This project is an assignment submission for the fulfillment of the module ICT2202 Digital Forensics.
<br /><br />
As such, copyright and any rights to this project shall belong to the project contributors as well as to [Singapore Institute of Technology (SIT)](https://www.singaporetech.edu.sg/).
<br /><br />
Plagiarism is a serious offence, and SIT's policy explicitly forbids such acts. Any submission caught with plagiarised work shall receive zero marks for their submission.
<br /><br />
Any third-party resources used for this project may be reused in accordance to their license and/ or terms and conditions.
