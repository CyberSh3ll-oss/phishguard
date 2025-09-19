📄 README.md
# 🛡️ PhishGuard — Simple Phishing Website Detection Tool

PhishGuard is a **Python-based command-line tool** that detects potential phishing websites.  
It uses **blacklist checks, redirect inspection, and heuristic analysis** to flag suspicious URLs as:

- ✅ SAFE  
- ⚠️ POTENTIALLY DANGEROUS  
- ❌ PHISHING  

This project was developed as part of a **college 3-credit course** to demonstrate practical cybersecurity concepts in Python.

---

## ✨ Features

- 🔒 **Local Blacklist Check** – compare against known malicious domains.  
- 🔗 **Redirect Chain Inspection** – detect hidden redirections to suspicious sites.  
- 🕵️ **Heuristic Analysis**  
  - IP-based domains  
  - Suspicious keywords (`login`, `secure`, `bank`, etc.)  
  - Long/obfuscated URLs  
  - `@` trick in URLs  
  - Multiple subdomains (cloaking technique)  
- 🧮 **Scoring System** – assigns risk score and provides a clear verdict.  
- 📦 **Lightweight** – no heavy dependencies, runs in Linux terminal.  

---

## 📂 Project Structure



phishguard_simple.py # main Python script
blacklist.txt # local blacklist (sample domains)
requirements.txt # Python dependencies
LICENSE # project license (MIT / Apache 2.0)
README.md # project documentation


---

## ⚙️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/phishguard.git
   cd phishguard


Create a virtual environment (optional but recommended)

python3 -m venv venv
source venv/bin/activate


Install dependencies

pip install -r requirements.txt

🚀 Usage
Basic Scan
python phishguard_simple.py "http://example.com"

With Custom Blacklist
python phishguard_simple.py "http://malicious.site" --blacklist my_blacklist.txt

📊 Example Output
[PhishGuard] Scanning: http://192.168.1.5/login

--- Verdict ---
URL: http://192.168.1.5/login
Score: 52
Verdict: PHISHING

Checks:
  blacklist: False
  valid_url: True
  http_ok: True
  http_status: 200
  final_url: http://192.168.1.5/login
  heuristic_score: 37
  heuristic_reasons: ['Host is an IP address',
                      'Suspicious keyword: login']

Indicators / reasons:
 - Host is an IP address
 - Suspicious keyword: 'login'

📘 How It Works

Blacklist Check
Compares the URL against entries in blacklist.txt.

Redirect Inspection
Follows redirects and warns if the final domain differs.

Heuristic Scoring
Analyzes the URL for common phishing tricks:

IP instead of domain

Suspicious keywords

Long or obfuscated URLs

@ symbol redirection

Multiple subdomains

Final Verdict
Based on total score:

SAFE (0–14)

POTENTIALLY DANGEROUS (15–39)

PHISHING (40+)

🧾 Requirements

Python 3.7+

Dependencies (install via requirements.txt):

requests

validators

tldextract

📜 License

This project is licensed under the apache2.0 License – see the LICENSE
 file for details.

🙌 Acknowledgements

Built as part of a college cybersecurity project.

Inspired by real-world phishing detection techniques.

Uses open-source Python libraries (requests, validators, tldextract).


---

## 📄 `phishguard_simple.py`

*(This is the main script you run)*

```python
#!/usr/bin/env python3
"""
PhishGuard — simple CLI phishing URL scanner (college project / 3 credits)
"""
import argparse
import os
import re
from urllib.parse import urlparse

import requests
import tldextract
import validators

# ---------- Config ----------
BLACKLIST_FILE = "blacklist.txt"
TIMEOUT = 6
SUSPICIOUS_KEYWORDS = ("login", "secure", "account", "update", "verify",
                       "bank", "confirm", "signin", "paypal", "apple", "reset")
# ----------------------------

def normalize_url(u: str) -> str:
    if "://" not in u:
        u = "http://" + u
    return u

def load_blacklist(path: str) -> set:
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln.strip().lower() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    return set(lines)

def domain_of(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    return parsed.netloc.lower()

def is_ip_host(host: str) -> bool:
    return re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) is not None

def quick_http_info(url: str):
    try:
        r = requests.get(normalize_url(url), timeout=TIMEOUT, allow_redirects=True,
                         headers={"User-Agent": "PhishGuard/1.0"})
        final = r.url
        return True, final, r.status_code, None
    except Exception as e:
        return False, None, None, str(e)

def heuristic_score(url: str):
    score = 0
    reasons = []
    norm = normalize_url(url).lower()
    host = domain_of(norm)
    full = norm

    if is_ip_host(host.split(":")[0]):
        score += 30
        reasons.append("Host is an IP address")

    if len(full) > 80:
        score += 8
        reasons.append("URL length > 80")

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in full:
            score += 7
            reasons.append(f"Suspicious keyword: '{kw}'")

    if "@" in full:
        score += 15
        reasons.append("Contains '@' (credential-steering trick)")

    extracted = tldextract.extract(full)
    sub = extracted.subdomain or ""
    if sub.count(".") >= 2:
        score += 5
        reasons.append("Many subdomains (possible cloak)")

    path = urlparse(full).path or ""
    if "//" in path:
        score += 4
        reasons.append("Double slashes in path")

    return score, reasons

def verdict(score: int) -> str:
    if score >= 40:
        return "PHISHING"
    if score >= 15:
        return "POTENTIALLY DANGEROUS"
    return "SAFE"

def analyze(url: str, blacklist_path: str):
    out = {"url": url, "score": 0, "indicators": [], "checks": {}}
    bl = load_blacklist(blacklist_path)

    u_low = url.lower().strip()
    host = domain_of(u_low)
    if u_low in bl or host in bl:
        out["score"] += 60
        out["indicators"].append("Found in local blacklist")
        out["checks"]["blacklist"] = True
    else:
        out["checks"]["blacklist"] = False

    is_valid = validators.url(normalize_url(url))
    out["checks"]["valid_url"] = bool(is_valid)
    if not is_valid:
        out["score"] += 6
        out["indicators"].append("Malformed or suspicious URL format")

    ok, final, status, err = quick_http_info(url)
    out["checks"]["http_ok"] = ok
    out["checks"]["http_status"] = status
    out["checks"]["final_url"] = final
    if not ok:
        out["score"] += 8
        out["indicators"].append(f"Request failed: {err}")
    else:
        final_host = domain_of(final)
        if final_host != host:
            out["score"] += 6
            out["indicators"].append(f"Redirects to different domain: {final_host}")
        parsed = urlparse(normalize_url(final))
        if parsed.scheme != "https":
            out["score"] += 5
            out["indicators"].append("No HTTPS on final URL")

    hscore, hreasons = heuristic_score(url)
    out["checks"]["heuristic_score"] = hscore
    out["checks"]["heuristic_reasons"] = hreasons
    out["score"] += hscore
    out["indicators"].extend(hreasons)

    out["final_verdict"] = verdict(out["score"])
    return out

def main():
    ap = argparse.ArgumentParser(description="PhishGuard — simple phishing URL checker")
    ap.add_argument("url", help="URL or domain to scan")
    ap.add_argument("--blacklist", default=BLACKLIST_FILE, help="path to local blacklist file")
    args = ap.parse_args()

    print(f"[PhishGuard] Scanning: {args.url}")
    res = analyze(args.url, args.blacklist)

    print("\n--- Verdict ---")
    print("URL:", res["url"])
    print("Score:", res["score"])
    print("Verdict:", res["final_verdict"])
    print("\nChecks:")
    for k, v in res["checks"].items():
        print(f"  {k}: {v}")
    if res["indicators"]:
        print("\nIndicators / reasons:")
        for r in res["indicators"]:
            print(" -", r)

if __name__ == "__main__":
    main()

📄 requirements.txt
requests
validators
tldextract

📄 blacklist.txt (sample)
# Example malicious domains
bad.example.com
phishing-login.net
http://tiny.phish/abc

📄 LICENSE (apache 2.0)
apache2.0 License

Copyright (c) 2025 CyberSh3ll0-oss

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---------------------------------------------------------------
NOTICE: This product includes software developed by CyberSh3ll0-oss.
---------------------------------------------------------------


                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

1. Definitions.

   "License" shall mean the terms and conditions for use, reproduction,
   and distribution as defined by Sections 1 through 9 of this document.

   "Licensor" shall mean the copyright owner or entity authorized by
   the copyright owner that is granting the License.

   "Legal Entity" shall mean the union of the acting entity and all
   other entities that control, are controlled by, or are under common
   control with that entity. For the purposes of this definition,
   "control" means (i) the power, direct or indirect, to cause the
   direction or management of such entity, whether by contract or
   otherwise, or (ii) ownership of fifty percent (50%) or more of the
   outstanding shares, or (iii) beneficial ownership of such entity.

   "You" (or "Your") shall mean an individual or Legal Entity
   exercising permissions granted by this License.

   "Source" form shall mean the preferred form for making modifications,
   including but not limited to software source code, documentation
   source, and configuration files.

   "Object" form shall mean any form resulting from mechanical
   transformation or translation of a Source form, including but
   not limited to compiled object code, generated documentation,
   and conversions to other media types.

   "Work" shall mean the work of authorship, whether in Source or
   Object form, made available under the License, as indicated by a
   copyright notice that is included in or attached to the work
   (an example is provided in the Appendix below).

   "Derivative Works" shall mean any work, whether in Source or Object
   form, that is based on (or derived from) the Work and for which the
   editorial revisions, annotations, elaborations, or other modifications
   represent, as a whole, an original work of authorship. For the purposes
   of this License, Derivative Works shall not include works that remain
   separable from, or merely link (or bind by name) to the interfaces of,
   the Work and Derivative Works thereof.

   "Contribution" shall mean any work of authorship, including
   the original version of the Work and any modifications or additions
   to that Work or Derivative Works thereof, that is intentionally
   submitted to Licensor for inclusion in the Work by the copyright owner
   or by an individual or Legal Entity authorized to submit on behalf of
   the copyright owner. For the purposes of this definition, "submitted"
   means any form of electronic, verbal, or written communication sent
   to the Licensor or its representatives, including but not limited to
   communication on electronic mailing lists, source code control systems,
   and issue tracking systems that are managed by, or on behalf of, the
   Licensor for the purpose of discussing and improving the Work, but
   excluding communication that is conspicuously marked or otherwise
   designated in writing by the copyright owner as "Not a Contribution."

   "Contributor" shall mean Licensor and any individual or Legal Entity
   on behalf of whom a Contribution has been received by Licensor and
   subsequently incorporated within the Work.

2. Grant of Copyright License. Subject to the terms and conditions of
   this License, each Contributor hereby grants to You a perpetual,
   worldwide, non-exclusive, no-charge, royalty-free, irrevocable
   copyright license to reproduce, prepare Derivative Works of,
   publicly display, publicly perform, sublicense, and distribute the
   Work and such Derivative Works in Source or Object form.

3. Grant of Patent License. Subject to the terms and conditions of
   this License, each Contributor hereby grants to You a perpetual,
   worldwide, non-exclusive, no-charge, royalty-free, irrevocable
   (except as stated in this section) patent license to make, have made,
   use, offer to sell, sell, import, and otherwise transfer the Work,
   where such license applies only to those patent claims licensable
   by such Contributor that are necessarily infringed by their
   Contribution(s) alone or by combination of their Contribution(s)
   with the Work to which such Contribution(s) was submitted. If You
   institute patent litigation against any entity (including a
   cross-claim or counterclaim in a lawsuit) alleging that the Work
   or a Contribution incorporated within the Work constitutes direct
   or contributory patent infringement, then any patent licenses
   granted to You under this License for that Work shall terminate
   as of the date such litigation is filed.

4. Redistribution. You may reproduce and distribute copies of the
   Work or Derivative Works thereof in any medium, with or without
   modifications, and in Source or Object form, provided that You
   meet the following conditions:

   (a) You must give any other recipients of the Work or
       Derivative Works a copy of this License; and

   (b) You must cause any modified files to carry prominent notices
       stating that You changed the files; and

   (c) You must retain, in the Source form of any Derivative Works
       that You distribute, all copyright, patent, trademark, and
       attribution notices from the Source form of the Work,
       excluding those notices that do not pertain to any part of
       the Derivative Works; and

   (d) If the Work includes a "NOTICE" text file as part of its
       distribution, then any Derivative Works that You distribute must
       include a readable copy of the attribution notices contained
       within such NOTICE file, excluding those notices that do not
       pertain to any part of the Derivative Works, in at least one
       of the following places: within a NOTICE text file distributed
       as part of the Derivative Works; within the Source form or
       documentation, if provided along with the Derivative Works; or,
       within a display generated by the Derivative Works, if and
       wherever such third-party notices normally appear. The contents
       of the NOTICE file are for informational purposes only and
       do not modify the License. You may add Your own attribution
       notices within Derivative Works that You distribute, alongside
       or as an addendum to the NOTICE text from the Work, provided
       that such additional attribution notices cannot be construed
       as modifying the License.

   You may add Your own copyright statement to Your modifications and
   may provide additional or different license terms and conditions
   for use, reproduction, or distribution of Your modifications, or
   for any such Derivative Works as a whole, provided Your use,
   reproduction, and distribution of the Work otherwise complies with
   the conditions stated in this License.

5. Submission of Contributions. Unless You explicitly state otherwise,
   any Contribution intentionally submitted for inclusion in the Work
   by You to the Licensor shall be under the terms and conditions of
   this License, without any additional terms or conditions.
   Notwithstanding the above, nothing herein shall supersede or modify
   the terms of any separate license agreement you may have executed
   with Licensor regarding such Contributions.

6. Trademarks. This License does not grant permission to use the trade
   names, trademarks, service marks, or product names of the Licensor,
   except as required for reasonable and customary use in describing the
   origin of the Work and reproducing the content of the NOTICE file.

7. Disclaimer of Warranty. Unless required by applicable law or
   agreed to in writing, Licensor provides the Work (and each
   Contributor provides its Contributions) on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   implied, including, without limitation, any warranties or conditions
   of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
   PARTICULAR PURPOSE. You are solely responsible for determining the
   appropriateness of using or redistributing the Work and assume any
   risks associated with Your exercise of permissions under this License.

8. Limitation of Liability. In no event and under no legal theory,
   whether in tort (including negligence), contract, or otherwise,
   unless required by applicable law (such as deliberate and grossly
   negligent acts) or agreed to in writing, shall any Contributor be
   liable to You for damages, including any direct, indirect, special,
   incidental, or consequential damages of any character arising as a
   result of this License or out of the use or inability to use the
   Work (including but not limited to damages for loss of goodwill,
   work stoppage, computer failure or malfunction, or any and all
   other commercial damages or losses), even if such Contributor
   has been advised of the possibility of such damages.

9. Accepting Warranty or Additional Liability. While redistributing
   the Work or Derivative Works thereof, You may choose to offer,
   and charge a fee for, acceptance of support, warranty, indemnity,
   or other liability obligations and/or rights consistent with this
   License. However, in accepting such obligations, You may act only
   on Your own behalf and on Your sole responsibility, not on behalf
   of any other Contributor, and only if You agree to indemnify,
   defend, and hold each Contributor harmless for any liability
   incurred by, or claims asserted against, such Contributor by reason
   of your accepting any such warranty or additional liability.

END OF TERMS AND CONDITIONS
