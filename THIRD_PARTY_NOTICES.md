# Third-Party Notices

The ATTACK-Navi application code is released under the MIT License (see `LICENSE`). That license covers the code written for this repository. It does not cover the third-party content that the repository, the GitHub Pages site and the Docker image redistribute, which is listed here together with the license or terms that apply to it. This file is copied into every build as `assets/THIRD_PARTY_NOTICES.md` and is linked from Settings > Data in the application.

Licenses of the npm packages compiled into the application bundle are not listed here: the production build writes them to `dist/mitre-mitigation-navigator/3rdpartylicenses.txt`. That file sits one level above the `browser/` directory that the GitHub Pages deploy and the Docker image publish, so it is part of the build output but is not served by either deployment; `package-lock.json` in the repository is the authoritative list of those packages.

Nothing in this file is legal advice. If you redistribute this project or its data, read the upstream terms linked below.

## 1. Content bundled in this repository

### 1.1 MITRE ATT&CK®

| What | Where |
|---|---|
| ATT&CK Enterprise 19.2 STIX 2.1 bundle | `src/assets/data/enterprise-attack.json` |
| ATT&CK for ICS 18.1 STIX 2.1 bundle | `src/assets/data/ics-attack.json` |
| ATT&CK Mobile 18.1 STIX 2.1 bundle | `src/assets/data/mobile-attack.json` |
| ATT&CK technique and tactic identifiers and names inside the project's layer files | `src/assets/data/library-layers/`, `src/assets/data/lylat-mission-layers/`, `src/assets/data/cve-technique-map.json`, curated tables in `src/app/services/` |

Source: https://github.com/mitre-attack/attack-stix-data (the live copy that the application fetches comes from the same repository). The bundles are reproduced under the ATT&CK license, which requires the following statement to accompany any copy:

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

ATT&CK license text (https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt):

> The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.
>
> "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."
>
> Disclaimers
>
> MITRE does not claim ATT&CK enumerates all possibilities for the types of actions and behaviors documented as part of its adversary model and framework of techniques. Using the information contained within ATT&CK to address or cover full categories of techniques will not guarantee full defensive coverage as there may be undisclosed techniques or variations on existing techniques not documented by ATT&CK.
>
> ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN ARE PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE ORGANIZATION HE/SHE REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF TRUSTEES, OFFICERS, AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with, sponsored by, or endorsed by MITRE. Terms of use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/

### 1.2 Center for Threat-Informed Defense F3 (Fight Financial Fraud Framework)

| What | Where |
|---|---|
| F3 STIX 2.1 bundle (ATT&CK-style tactics and techniques for financial fraud) | `src/assets/data/f3-attack.json` |

Source: https://github.com/center-for-threat-informed-defense/fight-fraud-framework, published by the Center for Threat-Informed Defense (MITRE Engenuity). License: Apache License 2.0 (full text in Appendix A).

### 1.3 CWE™ (Common Weakness Enumeration)

| What | Where |
|---|---|
| CWE identifiers, names and short descriptions used for CWE lookups | `src/assets/data/cwe-catalog.json`, `src/assets/data/cwe-exploitation-anchor.json` (identifiers only) |

Source: https://cwe.mitre.org/. CWE terms of use (https://cwe.mitre.org/about/termsofuse.html):

> The MITRE Corporation hereby grants you a non-exclusive, royalty-free license to use CWE for research, development, and commercial purposes. Any copy you make for such purposes is authorized on the condition that you reproduce MITRE's copyright designation and this license in any such copy.

CWE is a trademark of The MITRE Corporation. Copyright © The MITRE Corporation.

### 1.4 CERT/CC SSVC decision tables

| What | Where |
|---|---|
| CISA Coordinator SSVC v2.0.3 and CISA BOD 26-04 Remediation Timelines v1.0.0 decision tables, fetched by `scripts/build-ssvc-tables.mjs` | `src/assets/data/ssvc-decision-tables.json` |

Source: https://github.com/CERTCC/SSVC (`data/csv/cisa/`). The `data/` directory of that repository is licensed as follows (https://github.com/CERTCC/SSVC/blob/main/data/LICENSE):

> Copyright 2026 Carnegie Mellon University.
>
> Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
> [...] NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

CERT Coordination Center® is registered in the U.S. Patent and Trademark Office by Carnegie Mellon University. The SSVC documentation (as opposed to the data files) is licensed CC BY-NC 4.0 and is not reproduced here.

### 1.5 NVD, CVE®, EPSS and KEV derived data

| What | Where |
|---|---|
| CVE identifiers grouped by ATT&CK technique, generated from NVD records by `scripts/build-cve-technique-map.mjs` | `src/assets/data/cve-technique-map.json`, `src/assets/data/cve-technique-counts.json` |
| Pre-built CVE dossiers: NVD description, CVSS, published date; EPSS score and percentile; CISA KEV fields; derived SSVC, CWE, CAPEC and ATT&CK context | `src/assets/data/dossiers/*.json` |

- **NVD (NIST).** The CVE records come from the NIST National Vulnerability Database API. The NVD terms of use (https://nvd.nist.gov/developers/terms-of-use) ask services that use the API to display this notice, which the application shows in Settings > Data:

  > This product uses the NVD API but is not endorsed or certified by the NVD.

  NVD content is produced by the National Institute of Standards and Technology, a U.S. federal agency, and is made available as a public service. The NVD name is used here only to identify the source of the data and not to imply endorsement. Content that this project derives from NVD data (the CVE-to-technique mapping, SSVC outcomes, kill-chain context) is this project's own interpretation and is not attributed to the NVD.

- **CVE® Program.** CVE identifiers and descriptions are used under the CVE terms of use (https://www.cve.org/Legal/TermsOfUse):

  > CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE™). Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.

  Copyright © The MITRE Corporation. CVE is a trademark of The MITRE Corporation.

- **EPSS (FIRST).** Exploit Prediction Scoring System scores in the dossiers come from the FIRST EPSS API (https://www.first.org/epss/). EPSS scores are published freely without registration; FIRST asks for attribution when EPSS data is used in publications or products. EPSS is maintained by the EPSS Special Interest Group at FIRST.

- **CISA Known Exploited Vulnerabilities.** KEV fields come from the CISA KEV catalog as mirrored at https://github.com/cisagov/kev-data, distributed under the Creative Commons CC0 1.0 Universal public domain dedication. Use of the data does not authorize use of the CISA logo or DHS seal and does not imply endorsement by CISA or DHS.

### 1.6 MITRE D3FEND™ offline seed

| What | Where |
|---|---|
| Editorial seed of about 97 D3FEND countermeasure identifiers, names and one-line definitions, used only until the live D3FEND API responds | `src/app/services/d3fend.service.ts` |

Source: https://d3fend.mitre.org/. D3FEND terms of use (https://d3fend.mitre.org/tou/):

> The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use D3FEND for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.

Copyright © The MITRE Corporation. Approved for Public Release; Distribution Unlimited. MITRE D3FEND and the MITRE D3FEND logo are trademarks of The MITRE Corporation. The D3FEND ontology repository (https://github.com/d3fend/d3fend-ontology) is published under the MIT License. The seed is an editorial subset and is not an official D3FEND export; the application replaces it with live data whenever the API responds.

### 1.7 MITRE Cyber Analytics Repository (CAR) offline seed

| What | Where |
|---|---|
| Seed of CAR analytic identifiers, names, descriptions, platforms and pseudocode, used as a fallback until the live CAR layer loads | `src/app/services/car.service.ts` |

Source: https://github.com/mitre-attack/car. Copyright The MITRE Corporation. License: Apache License 2.0 (full text in Appendix A).

### 1.8 Detection query library

| What | Where |
|---|---|
| Per-technique SIEM queries for Splunk, Elastic, Microsoft, Chronicle and CrowdStrike platforms | `src/assets/technique-queries.json` |

The queries were authored for this repository, seeded from and informed by the following open rule sets. Where an entry reproduces or closely follows an upstream rule, that rule's license applies:

| Rule set | License |
|---|---|
| SigmaHQ/sigma (https://github.com/SigmaHQ/sigma) | Detection Rule License (DRL) 1.1 |
| splunk/security_content (https://github.com/splunk/security_content) | Apache License 2.0 |
| elastic/detection-rules (https://github.com/elastic/detection-rules) | Elastic License 2.0 |
| microsoft/Microsoft-365-Defender-Hunting-Queries (https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries) | MIT License |
| chronicle/detection-rules (https://github.com/chronicle/detection-rules) | Apache License 2.0 |

### 1.9 Lucide icons

| What | Where |
|---|---|
| Inline SVG icon shapes adapted from Lucide | `src/app/shared/icons/icon-registry.ts` |

Source: https://lucide.dev / https://github.com/lucide-icons/lucide. License (https://github.com/lucide-icons/lucide/blob/main/LICENSE):

> ISC License
>
> Copyright (c) 2026 Lucide Icons and Contributors
>
> Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
>
> THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

Lucide icons that derive from the Feather project (the list is in the Lucide LICENSE file) are additionally covered by:

> The MIT License (MIT)
>
> Copyright (c) 2013-present Cole Bemis
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### 1.10 Content authored in this repository

The library inventory (`src/assets/library.json`), the library and mission layers (`src/assets/data/library-layers/`, `src/assets/data/lylat-mission-layers/`), the CWE exploitation anchor (`src/assets/data/cwe-exploitation-anchor.json`), and the curated tables in the services marked with a `PROVENANCE` comment (Zeek, Suricata and YARA templates, Wazuh, IR playbooks, offensive tools, C2, BloodHound, Azure identity, event logging, IOC feed associations, PayloadsAllTheThings mapping, compliance mapper) are this project's own work under the MIT License. They reference ATT&CK identifiers and names, which remain ATT&CK content under section 1.1. None of them is an official MITRE mapping.

## 2. Content fetched at runtime

The application also loads data from the services below while it runs. That data is not stored in this repository or in the build; it remains subject to each source's own terms, which the user of a deployment accepts by using it.

| Source | Host | License or terms |
|---|---|---|
| MITRE ATT&CK STIX (live refresh) | raw.githubusercontent.com/mitre-attack/attack-stix-data | ATT&CK license (section 1.1) |
| CAPEC™ STIX (via mitre/cti) | raw.githubusercontent.com/mitre/cti | CAPEC terms of use (https://capec.mitre.org/about/termsofuse.html): non-exclusive, royalty-free license for research, development and commercial purposes, provided MITRE's copyright designation and the license accompany any copy. CAPEC and the CAPEC logo are trademarks of The MITRE Corporation. |
| MITRE D3FEND knowledge graph API | d3fend.mitre.org | D3FEND terms of use (section 1.6) |
| MITRE Engage™ | raw.githubusercontent.com/mitre/engage | Apache License 2.0 |
| MITRE CAR Navigator layer | raw.githubusercontent.com/mitre-attack/car | Apache License 2.0 |
| Center for Threat-Informed Defense Mappings Explorer (NIST 800-53, AWS, Azure, GCP, CRI, VERIS, CSA CCM, M365, KEV mappings) | raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer | Apache License 2.0 |
| Center for Threat-Informed Defense ATT&CK-to-CVE methodology | raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve | Apache License 2.0 |
| Atomic Red Team and Invoke-AtomicRedTeam (Red Canary) | raw.githubusercontent.com/redcanaryco | MIT License |
| SigmaHQ rules | raw.githubusercontent.com/SigmaHQ/sigma | Detection Rule License (DRL) 1.1 |
| mdecrevoisier/SIGMA-detection-rules | raw.githubusercontent.com/mdecrevoisier, api.github.com | CC0 1.0 Universal |
| OTRF ThreatHunter-Playbook | raw.githubusercontent.com/OTRF | MIT License |
| MISP galaxy clusters | raw.githubusercontent.com/MISP/misp-galaxy | Dual-licensed CC0 1.0 Universal or the MIT-style license in the repository's LICENSE.md |
| CISA Known Exploited Vulnerabilities | raw.githubusercontent.com/cisagov/kev-data, www.cisa.gov | CC0 1.0 Universal (section 1.5) |
| NIST NVD CVE API 2.0 | services.nvd.nist.gov | NVD terms of use (section 1.5); the application sends the user's own API key only as a request header |
| FIRST EPSS API | api.first.org | Free to use; attribution requested (section 1.5) |
| trickest/cve (proof-of-concept index) | github.com/trickest/cve | MIT License |
| Galeax/CVE2CAPEC | raw.githubusercontent.com/Galeax/CVE2CAPEC | GNU General Public License v3.0 (data is read at runtime, not bundled) |
| stamparm/ipsum (IP reputation feed) | raw.githubusercontent.com/stamparm/ipsum | The Unlicense |
| swisskyrepo/PayloadsAllTheThings | github.com/swisskyrepo/PayloadsAllTheThings | MIT License |
| mukul975/Anthropic-Cybersecurity-Skills Navigator layer | raw.githubusercontent.com/mukul975 | Apache License 2.0 |
| Exploit Database mirror | gitlab.com/exploit-database/exploitdb | Exploit-DB's own terms |
| Google Fonts stylesheets | fonts.googleapis.com, fonts.gstatic.com | Each font family's license as listed on fonts.google.com; served by Google |
| User-configured MISP, OpenCTI and TAXII servers | operator-defined | The operator's own agreements with those services |

## 3. Trademarks

MITRE ATT&CK®, ATT&CK®, CVE® and the corresponding logos are registered trademarks, and CAPEC™, CWE™, D3FEND™, Engage™ and CAR are trademarks, of The MITRE Corporation. CERT Coordination Center® is a registered trademark of Carnegie Mellon University. Other names are the property of their respective owners. Their use in this project identifies the source of data and does not imply affiliation, sponsorship or endorsement.

## Appendix A: Apache License 2.0

Applies to the F3 bundle (section 1.2), the CAR seed (section 1.7) and the runtime sources marked Apache License 2.0 in section 2.

```
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

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```
