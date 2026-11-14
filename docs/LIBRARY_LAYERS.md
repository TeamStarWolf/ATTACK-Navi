<!-- ATTACK-Navi - Copyright (c) 2026 TeamStarWolf - MIT License -->
# Library Layers Guide

**Library layers** are curated MITRE ATT&CK Navigator overlays bundled with ATT&CK-Navi. Select one from the **Library Layers** picker in the matrix controls and the workbench colors each technique cell by that layer's score, letting you see a theme, a data-driven frequency, or a specific adversary's documented behavior projected onto the ATT&CK matrix. This build ships **201 layers**.

Counts below are distinct technique IDs in each layer, not technique/tactic rows or machine counts. The inventory is checked against the [bundled manifest](../src/assets/data/library-layers/index.json); the bundled layers target the bundled Enterprise ATT&CK v19.2 snapshot. Every other Navigator layer the TeamStarWolf library publishes is synced in beside them (see [Synced from the library](#synced-from-the-library)).

## How to use them

- Open the **Library Layers** section of the matrix controls and pick a layer; the matrix recolors immediately. The layers are grouped (bundled groups first: Curated themes, Threat groups, HTB frequency, Agentic AI, Lylat; then the synced groups); a group heading opens or closes its list, and the search box filters every group by name.
- **Cell color = score.** For curated layers, score encodes a membership tier (core vs supporting). For the frequency layer, score is a normalized count. For threat-group layers, every colored cell is a documented technique (score 100).
- Layers are **overlays for exploration**, not authoritative coverage claims. Switch layers to compare, e.g. overlay a threat group, then a control theme, to reason about gaps.
- The picker reads `src/assets/data/library-layers/index.json` at runtime, so the set grows without any code change.

## Reading the scores & provenance

| Layer type | Score meaning | Source |
|---|---|---|
| Curated theme / weakness | Membership tier (core = 100, supporting = 55) or membership-only | TeamStarWolf reference library + checked against bundled ATT&CK data. **Not** an official MITRE mapping. |
| HTB frequency views | Normalized machine count (100 = most frequent technique within that layer) | Derived technique metadata only; broad, core, OS, and difficulty views have different cohorts/methods. Reflects HTB teaching bias, not enterprise prevalence. |
| Agentic AI Swarm | Event frequency across a de-identified 8-phase intrusion | Illustrative composite pattern; ATT&CK x ATLAS. Not an attribution of any specific incident. |
| Threat Group emulation | 100 = MITRE-documented use | Generated directly from MITRE's `intrusion-set --uses--> technique` relationships. **MITRE's own attribution.** |

## Application & Weakness (curated)

| Layer | Techniques | Notes |
|---|---|---|
| Web Application Attacks | 32 | Web and API intrusion paths, including application exploitation, account abuse, session theft, and data access |
| OWASP Top 10 (2021) | 14 | Connects the library's OWASP Top 10 (2021) themes with relevant attacker behaviors |
| CWE Weakness Classes | 98 | Connects CWE weakness classes to ATT&CK behaviors through explicit CAPEC links in the library |
| CAPEC Families | 19 | Shows techniques explicitly linked to broad CAPEC Meta patterns in the library |

## Infrastructure & Platform (curated)

| Layer | Techniques | Notes |
|---|---|---|
| Cloud Attacks | 23 | Covers selected cloud intrusion behaviors, from account and token abuse to data theft and destructive impact |
| Active Directory | 28 | Covers domain reconnaissance, credential theft, Kerberos and NTLM abuse, certificate attacks, and remote access |
| Container and Kubernetes Attacks | 9 | Covers container deployment, image abuse, host escape, workload discovery, and unauthorized compute use |
| macOS & Linux Attacks | 39 | Selected Unix/macOS behaviors; a technique may apply to either platform, not necessarily both. Per-row platform metadata narrows scope |

## Campaign & Behavior (curated)

| Layer | Techniques | Notes |
|---|---|---|
| Ransomware TTPs | 14 | Follows common ransomware intrusion themes through access, credential theft, movement, exfiltration, encryption, and recovery inhibition |
| Insider Threat | 23 | Curated abuse of granted access, collection, export, and sabotage; behavior matches do not establish malicious intent |
| Impact: Destruction, Extortion & Disruption | 25 | Enterprise impact behaviors with supporting theft/preparation; a planning view, not a destructive execution runbook |

## Cross-Tactic Technique Themes (curated)

| Layer | Techniques | Notes |
|---|---|---|
| Living-off-the-Land (LOTL) | 59 | Signed/legitimate binaries, interpreters, and admin tooling abused across execution, evasion, movement, and exfiltration |
| Phishing & Social Engineering | 36 | Lure delivery, user execution, and account/MFA abuse enabling human-targeted initial access |
| Supply Chain & Trusted-Relationship Compromise | 36 | Third-party, software/hardware supply-chain, and trusted-relationship intrusion paths |
| Data Collection & Exfiltration | 47 | Collection, staging/packaging, and egress channels for data theft |
| Credential Theft & Abuse | 64 | Dumping, cracking, store/file harvesting, ticket/token theft, and credential reuse |

## Frequency Analysis

| Layer | Techniques | Machine cohort | Normalization maximum |
|---|---|---|---|
| [HTB Technique Frequency](../src/assets/data/library-layers/htb-technique-frequency.json) | 135 | 535: 131 careful originals + 404 keyword-derived additions | 494 machines |
| [HTB Core Techniques (528, precise)](../src/assets/data/library-layers/htb-core-techniques-528.json) | 21 | 528, one uniform precise-pattern pass | 494 machines |
| [HTB Linux Techniques](../src/assets/data/library-layers/htb-linux-techniques.json) | 19 | 347 Linux records from the 529-machine content cohort | 323 machines |
| [HTB Windows Techniques](../src/assets/data/library-layers/htb-windows-techniques.json) | 19 | 142 Windows records from the 529-machine content cohort | 135 machines |
| [HTB Easy Techniques](../src/assets/data/library-layers/htb-easy-techniques.json) | 20 | 109 Easy records from the 529-machine content cohort | 109 machines |
| [HTB Medium Techniques](../src/assets/data/library-layers/htb-medium-techniques.json) | 21 | 125 Medium records from the 529-machine content cohort | 125 machines |
| [HTB Hard Techniques](../src/assets/data/library-layers/htb-hard-techniques.json) | 21 | 82 Hard records from the 529-machine content cohort | 82 machines |
| [HTB Insane Techniques](../src/assets/data/library-layers/htb-insane-techniques.json) | 21 | 56 Insane records from the 529-machine content cohort | 54 machines |

These are text-derived training signals, not executed attack validation or enterprise prevalence estimates. Scores normalize to the most frequent technique **inside each layer**, not the cohort size: 100 is not a prevalence percentage. Compare technique mix and supporting counts, not raw normalized scores across layers. OS and difficulty subsets do not exhaust the 529-machine content cohort; inventory-only distributions use a different denominator and must not be substituted here.

The broad layer's current manifest describes 535 machines. The core layer's description still contains a stale comparison to an older 249-machine broad snapshot; this guide uses the current broad artifact, while preserving the separate 528-machine core provenance. Dataset/registry reconciliation is a separate data task, not an implicit refresh in this documentation change.

## AI & Emerging Threats

| Layer | Techniques | Notes |
|---|---|---|
| Agentic AI Swarm Intrusion | 74 | Enterprise ATT&CK frequency across a generalized agentic-AI-swarm kill chain: credential reuse, egress-relay C2, pipeline exploitation, and cluster takeover |

## Lylat Training Range (mission coverage)

Coverage from the Lylat Labs themed training missions (a companion training-range repository that is not published; its generated layers are vendored here). **Planned/training coverage only** — the missions are `execution_verified: false`, so these layers show which techniques each mission is *designed to exercise*, **not** a validated detection or coverage result. Not an official MITRE mapping.

**Curated overlay (in the picker):**

| Layer | Techniques | Notes |
|---|---|---|
| TeamStarWolf - Lylat Mission Coverage | 108 | Enterprise ATT&CK techniques across the 28 enterprise Lylat missions, scored by how many missions map each (normalized to the most-mapped technique). Planned/training coverage, not detection. Technique ids and tactic slugs are resolved against the bundled 19.2 snapshot (retired ids follow ATT&CK's revoked-by chain, e.g. T1070.001 -> T1685.005; pre-v19 `defense-evasion` rows become `stealth` / `defense-impairment`). |

**Per-mission + per-domain layers (vendored, one-click importable):** all 35 individual layers (31 per-mission + 4 per-domain coverage) are served from `src/assets/data/lylat-mission-layers/` (see its `index.json`). Load any one through the matrix controls' **Import Layer** action (or your instance's load-from-file/URL) — e.g. `assets/data/lylat-mission-layers/lylat-mission-katina-phish-01.json`. This keeps the curated picker uncluttered while making every mission's coverage available in the instance.

**Keeping them current:** the mission layers are generated upstream from mission front-matter written against earlier ATT&CK releases. `node scripts/normalize-lylat-layers.mjs` resolves every vendored row against the bundled snapshots (revoked-by successors, tactics from `kill_chain_phases`) and regenerates the per-domain coverage layers and the picker layer from the per-mission layers; `--check` reports drift without writing. Run it after every ATT&CK data refresh or re-vendoring, then `node scripts/validate-curated-threat-layers.mjs`, which fails on any unresolved id or tactic.

**Domain note:** the enterprise per-mission layers, the enterprise per-domain coverage layer, and the curated aggregate above render in the standard **enterprise-attack** matrix (bundled 19.2). The **ICS/OT** and **Mobile** mission layers render in the app's ICS and Mobile domains (bundled 19.2 as well); the **ATLAS** layer needs the MITRE **ATLAS Navigator** and will not resolve against any bundled matrix.

## Adversary Emulation - Threat Groups (MITRE attribution)

| Layer | Techniques | Notes |
|---|---|---|
| Threat Group: APT29 (G0016) | 66 | APT29 (G0016) adversary emulation overlay: 66 MITRE-documented techniques |
| Threat Group: Volt Typhoon (G1017) | 81 | Volt Typhoon (G1017) adversary emulation overlay: 81 MITRE-documented techniques |
| Threat Group: Scattered Spider (G1015) | 64 | Scattered Spider (G1015) adversary emulation overlay: 64 MITRE-documented techniques |
| Threat Group: Lazarus Group (G0032) | 93 | Lazarus Group (G0032) adversary emulation overlay: 93 MITRE-documented techniques |
| Threat Group: Sandworm Team (G0034) | 79 | Sandworm Team (G0034) adversary emulation overlay: 79 MITRE-documented techniques |
| Threat Group: FIN7 (G0046) | 67 | FIN7 (G0046) adversary emulation overlay: 67 MITRE-documented techniques |
| Threat Group: Turla (G0010) | 68 | Turla (G0010) adversary emulation overlay: 68 MITRE-documented techniques |
| Threat Group: APT41 (G0096) | 82 | APT41 (G0096) adversary emulation overlay: 82 MITRE-documented techniques |
| Threat Group: Kimsuky (G0094) | 109 | Kimsuky (G0094) adversary emulation overlay: 109 MITRE-documented techniques |
| Threat Group: MuddyWater (G0069) | 58 | MuddyWater (G0069) adversary emulation overlay: 58 MITRE-documented techniques |
| Threat Group: TeamTNT (G0139) | 56 | TeamTNT (G0139) adversary emulation overlay: 56 MITRE-documented techniques |

<!-- library-sync:start -->

## Synced from the library

These 164 layers come from the TeamStarWolf library's published Navigator set and its other Navigator folders, copied by `node scripts/sync-library-layers.mjs` (source address and sha256 of each in [library-sync.json](../src/assets/data/library-layers/library-sync.json)). They target ATT&CK v20 while the bundled data is v19.2, so an id the bundled data does not know is kept in the layer and listed in the lock; it has no cell to color until the ATT&CK data is refreshed. Layers in the ICS, Mobile and F3 domains color those matrices; ATLAS layers have no bundled matrix. Last synced 2026-11-14.

### Case studies (synced)

| Layer | Techniques | Notes |
|---|---|---|
| APT41 Public Record | 124 | Techniques from the public APT41 record, 2012 to 2026: what ATT&CK records for G0096 and campaigns C0017 and C0040, what vendor and government primaries state, and the study's own... |
| ATF Major Incident 2026 Case Study | 5 | Context techniques from ATT&CK's Qilin profile for the 2026 ATF major incident: the edge exploitation and phishing entry points and the encryption, recovery-inhibition and... |
| Before the Internet: Computer Threats, 1960 to 1990 | 31 | Techniques from the record of 1960 to 1990: guessed, cracked, default and logged passwords, trusted-host lateral movement and the Morris worm's exploited services, WANK's planted... |
| BeyondTrust Remote Support and PRA Command Injection of 2026 (CVE-2026-1731) Case Study | 16 | Techniques from the 2026 exploitation of the BeyondTrust Remote Support and PRA command injection CVE-2026-1731, from the reconnaissance surge and pre-authentication exploitation... |
| Binance Hot-Wallet Theft October 2026 Case Study | 11 | Techniques from the Binance theft record, from the tampered installer and the fake job assignment through the internal AI tool, the stolen deployment token and the container... |
| Boston Scientific Network Outage August 2026 Case Study | 2 | Candidate Initial Access techniques for the August 2026 Boston Scientific outage, where an external-facing network management device was the way in and the method was never stated. |
| CareCloud Medical-Records Breach March 2026 Case Study | 2 | Techniques from the CareCloud breach record of March 2026: the cloud account an unauthorized third party used inside one EHR environment for six days, and the patient data taken... |
| Change Healthcare Attack 2024 | 30 | Techniques from the Change Healthcare record, from the single-factor Citrix login to the February 2024 encryption, with ALPHV/BlackCat general tradecraft shown separately. |
| Check Point Gaia CVE-2026-123039, the PHP2Shell Chain, TSGA and the ESXi Wiper (2026) Case Study | 20 | Techniques from the 2026 Check Point gateway campaign, from PHP2Shell on unpatched Mobile Access portals and root through the Gaia DynamicCLI flaw CVE-2026-123039 to web shells... |
| Check Point Remote Access VPN IKEv1 Authentication Bypass of 2026 (CVE-2026-50751) Case Study | 4 | Techniques from the 2026 exploitation of the Check Point Remote Access VPN IKEv1 authentication bypass CVE-2026-50751, from the exploitation of internet-facing gateways and VPN... |
| Chrome Isolated Web Apps (2026) Case Study | 18 | Techniques bound to Chrome Isolated Web Apps in 2026: the extension and IWA persistence, SOCKS proxying and hiding that researchers demonstrated, the client-exploitation... |
| Cisco Catalyst SD-WAN Authentication Bypass (CVE-2026-20127) Case Study | 15 | Techniques from the Cisco Catalyst SD-WAN authentication bypass of 2026, from the peering bypass and the downgrade route to root to the SSH keys, account churn and log clearing... |
| Citrix NetScaler CVE-2026-3055 Case Study | 4 | Techniques from the 2026 exploitation of the NetScaler SAML IdP memory overread CVE-2026-3055, from the unauthenticated overread on the internet-facing appliance to an... |
| Citrix NetScaler Zero-Days (September and October 2026) Case Study | 15 | Techniques from the Citrix NetScaler zero-days of September and October 2026, from the August fingerprinting and the pre-authentication exploits to the web shells, the Python... |
| Collabora Built-in CODE Server (richdocumentscode) CVE-2026-110447 Case Study | 6 | Techniques from the Collabora Built-in CODE Server record, from the unauthenticated proxy.php command injection to the web shells and host discovery victims reported. |
| ConnectWise Cloud Backup Compromise October 2026 Case Study | 11 | Techniques from the ConnectWise Cloud Backup record: the password spray, sign-ins as a trusted vendor's multi-tenant app, stolen Graph tokens, a self-assigned Global Administrator... |
| cPanel and WHM Authentication Bypass of 2026 (CVE-2026-41940) Case Study | 6 | Techniques from the 2026 exploitation of the cPanel and WHM authentication bypass CVE-2026-41940, from the pre-authentication login-flow exploitation and the "Sorry" encryptor to... |
| Cyber Operations as Statecraft: The Hacker and the State Cases | 72 | Techniques from the government, court and vendor record of the state operations of 2006 to 2018: OPM, APT1, Regin, Sony Pictures, Shamoon, the 2016 US election, Bangladesh Bank... |
| Cybercrime and Hacktivism in Four Books Case Study | 19 | Techniques from the carding markets, DDoS extortion gangs, Anonymous and LulzSec, and the 1990 crackdown: phishing and point-of-sale sniffing, botnet floods, SQL injection... |
| Dell RecoverPoint for Virtual Machines Hard-Coded Credential Zero-Day of 2026 (CVE-2026-22769) Case Study | 8 | Techniques from the exploitation of the Dell RecoverPoint for Virtual Machines hard-coded credential CVE-2026-22769 by UNC6201 from mid-2024, from the shipped Tomcat Manager... |
| DentaQuest Health-Data Breach May 2026 Case Study | 5 | Techniques from the DentaQuest breach record of May 2026: one employee socially engineered out of credentials and an MFA code, the valid account that reached a network file share... |
| E-Commerce Threats: The Public Record, 1999 to 2026 | 23 | Techniques from the e-commerce card-theft record: supplier credentials and remote access into BA and Home Depot, Backoff's point-of-sale tradecraft, the Gonzalez ring's wireless... |
| eMudhra Certificate Authority Key Compromise 2026 Case Study | 7 | Techniques from the eMudhra record, from the weak intermediate keys anyone could recover and the certificates researchers forged with them to the interception and code-signing... |
| European Commission Cloud Breach 2026 Case Study | 17 | Techniques from the 2026 European Commission cloud breach: the AWS secret stolen through the poisoned Trivy scanner, the secret search, new access key and reconnaissance in the... |
| Exchange Server Mass Exploitation 2021 (Operation Exchange Marauder) Case Study | 44 | Techniques from the 2021 Exchange Server mass exploitation, from the ProxyLogon chain and HAFNIUM's mailbox theft to the ransomware, miners and ProxyShell actors that followed. |
| Fancy Bear Goes Phishing Cases | 73 | Techniques from the five cases in Fancy Bear Goes Phishing, from the Morris worm and the Dark Avenger to the DNC intrusions and Mirai. |
| FBI Surveillance System Breach 2026 Case Study | 2 | Techniques from the 2026 breach of an FBI system holding surveillance returns: the third-party path through a commercial ISP vendor's infrastructure and the reported exposure of... |
| FortiCloud SSO Authentication Bypass of 2026 (CVE-2026-24858) Case Study | 8 | Techniques from the January 2026 exploitation of the FortiCloud SSO authentication bypass CVE-2026-24858, from attacker-held FortiCloud accounts and the SSO login bypass to... |
| Ghostcat CVE-2020-1938 Case Study | 6 | Techniques from the Ghostcat record, from the unauthenticated AJP file read the lab demonstrated to the scanning and the follow-on stages it did not run. |
| GitLab CVE-2026-97229 Case Study | 6 | Techniques from the GitLab CVE-2026-97229 record, from code execution on an internet-facing server to the worker crashes and scanning GitLab's detections tag. |
| Hugging Face AI Supply Chain (Enterprise) | 24 | The Enterprise techniques behind the Hugging Face case study: malicious models, loader exploits, exposed tokens and the July 2026 pipeline intrusion. |
| ICS attacks 2024 to 2026 (Enterprise) | 79 | The IT-side techniques behind 2024 to 2026 ICS incidents: default accounts on exposed PLCs, edge-appliance exploitation and credential theft, the Poland wiper intrusion chain and... |
| ICS attacks 2024 to 2026 (ICS) | 43 | ATT&CK for ICS techniques mapped to 2023 to 2026 ICS incidents by CISA advisories AA25-343A and AA26-097A and by ATT&CK C0031, C0041, C0063, G1027, S1157, S1165 and S9046, as... ICS ATT&CK layer. 5 ids not in the bundled data (library-sync.json). |
| IDScan.net Driver's License Breach 2026 Case Study | 3 | Techniques from the 2026 IDScan.net driver's license breach: the access to the VeriScan cloud environment from 4 April to 2 September 2026 and what the Nexus search service let... |
| Instructure Canvas Breach 2026 Case Study | 9 | Techniques from the Instructure Canvas breach of 2026: the Free-for-Teacher account and support ticket, the cross-site scripting that yielded a support agent's token, the bulk... |
| Ivanti Connect Secure Zero-Day Chain (October 2026) Case Study | 22 | Techniques from the Ivanti Connect Secure zero-day chain of October 2026, from the authentication bypass and root escalation on a fully patched appliance to the in-memory... |
| Ivanti EPMM Code Injection (CVE-2026-1281 and CVE-2026-1340) Case Study | 13 | Techniques from the 2026 exploitation of the Ivanti EPMM code injection flaws CVE-2026-1281 and CVE-2026-1340, from unauthenticated code injection on the internet-facing MDM... |
| Kevin Mitnick Intrusions Case Study | 24 | Techniques from Kevin Mitnick's admitted conduct, the Christmas Day 1994 intrusion, two Art of Intrusion stories with a DOJ record, and the modern help desk vishing they... |
| Log4Shell (CVE-2021-44228) Case Study | 62 | Techniques from the Log4Shell record, from exploitation and scanning to the post-exploitation behavior of APT41, Aquatic Panda, Magic Hound and AvosLocker intrusions. |
| Magento and Adobe Commerce CVE-2026-48356 Case Study | 4 | Techniques from the PolyShell record, from the unauthenticated guest-cart upload to the webshells and storefront loaders Sansec reported. |
| Major Cloud Security Incidents, 2011 to 2026 | 48 | Techniques from the public record of cloud incidents: stolen and single-factor credentials, MFA request flooding and help-desk voice phishing, forged tokens and stolen OAuth and... |
| Microsoft Office Security Feature Bypass of 2026 (CVE-2026-21509) and APT28 Case Study | 19 | Techniques from the APT28 campaigns that exploited the Office security feature bypass CVE-2026-21509 in January 2026, from the spearphishing attachment and client exploitation to... |
| N-able N-central Able2Shell (November 2026) Case Study | 13 | Techniques from the Able2Shell record and the RMM attack surface, from scanning and exploitation of the exposed N-central server to the remote-control, tunnel and... |
| Node.js CVE-2026-111497 (Brotli Decoder) Case Study | 3 | Techniques bound to the Brotli decoder flaw in Node.js: server-side exploitation of Express routes that decode br bodies, client-side decoding, and denial of service. |
| Notepad++ Update-Channel Hijack CVE-2025-15556 Case Study | 21 | Techniques from the 2025 Notepad++ update-channel hijack behind CVE-2025-15556, from the redirected update and the malicious installer to DLL sideloading, the Chrysalis backdoor... |
| npm Supply-Chain Attacks, 2018 to 2026 | 30 | Techniques from eight years of npm supply-chain attacks, from hijacked maintainer accounts and poisoned release workflows to install-time payloads, token theft and exfiltration to... |
| NSA and CIA Tool Leaks 2016 to 2017 | 38 | Techniques from the leak record: the Equation group, the SMBv1 exploits reused by WannaCry and NotPetya, the M.E.Doc supply-chain vector, and the insider theft behind Vault 7. |
| Oracle PeopleSoft CVE-2026-35273 and ShinyHunters 2026 Case Study | 27 | Techniques from the Oracle PeopleSoft CVE-2026-35273 campaign of 2026, from the ShinyHunters zero-day wave against universities to the September WAF bypass, JSP web shells... |
| PAN-OS GlobalProtect Authentication Bypass of 2026 (CVE-2026-0257) Case Study | 18 | Techniques from the PAN-OS GlobalProtect authentication bypass of 2026, from the forged authentication override cookie and the unauthorized VPN session to the remote-access tools... |
| PHP 8.4.27, CVE-2026-109618 and CVE-2026-109619 Lab Study | 5 | Techniques from the record of the two PHP flaws fixed in 8.4.27, from unauthenticated exploitation of the web runtime to the follow-on behavior CISA tells defenders to watch for. |
| Plex Media Server Plex2Shell Chain (CVE-2026-96652, -96654, -96655, -96656) Case Study | 7 | Techniques from the Plex2Shell record, from the unauthenticated chain on exposed Plex Media Servers to the owner-token theft, the unsigned library load and the miners and... |
| ProFTPD mod_copy (CVE-2015-3306) Case Study | 4 | Techniques from the ProFTPD mod_copy record: the unauthenticated file copy the lab demonstrated, the web-shell path it did not, and the scanning AA26-281A describes. |
| Refrigeration-Controller Attacks on European Supermarkets and Blood Services, 2026 | 6 | Techniques from the 2026 refrigeration-controller attacks in Europe: Modbus scanning and the FOFA service, exposed and end-of-life controllers, default accounts and password... |
| Refrigeration-Controller Attacks on European Supermarkets and Blood Services, 2026 (ICS) | 8 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. |
| Sandworm operations Enterprise | 78 | Sandworm's Windows and edge-device tradecraft from the 2015 blackout through NotPetya, Olympic Destroyer, VPNFilter, Cyclops Blink and the 2022 attacks. |
| Sandworm operations ICS | 49 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. 3 ids not in the bundled data (library-sync.json). |
| SharePoint Server Exploitation Waves (2026) Case Study | 12 | Techniques from the 2026 SharePoint Server exploitation waves, from the eight KEV-listed CVEs and IIS machine-key theft to the web shells, tool tampering and Warlock encryption in... |
| SmarterTools SmarterMail Exploitation and Ransomware, 2026 (CVE-2026-23760, CVE-2026-24423, CVE-2025-52691) Case Study | 13 | Techniques from the 2026 exploitation of SmarterTools SmarterMail through CVE-2026-23760, CVE-2026-24423 and CVE-2025-52691, from scanning and the forced administrator password... |
| SolarWinds and SUNBURST 2019-2021 | 112 | Techniques from the SolarWinds and SUNBURST record, from the SUNSPOT build implant and the signed Orion backdoor to the Cobalt Strike loaders and the Golden SAML cloud follow-on. |
| SSHole OpenSSH CVE-2026-123158 Case Study | 15 | Techniques from the SSHole record, from the password-free login to an existing local account on musl builds without PAM to the authorized keys, new accounts, shadow-file reads and... |
| Stryker Device-Wipe Attack March 2026 Case Study | 11 | Techniques from the Stryker device-wipe record of March 2026: the Handala persona domains, a compromised Entra ID administrator path, a new Global Administrator and the built-in... |
| Stuxnet (S0603) Enterprise | 44 | The Windows side of Stuxnet: USB and network spread, privilege escalation, signed rootkit drivers and Step 7 project infection. |
| Stuxnet (S0603) ICS | 25 | ATT&CK for ICS techniques that ATT&CK v20.0 lists for Stuxnet (S0603), as bound in the Stuxnet case study. ICS ATT&CK layer. 1 id not in the bundled data (library-sync.json). |
| TeamPCP Supply-Chain Campaign of 2026 Case Study | 30 | Techniques from the 2026 TeamPCP supply-chain campaign, from the poisoned Trivy release and moved GitHub Actions tags to the runner secret theft, the stolen tokens that... |
| The Cuckoo's Egg Intrusion (LBL, 1986) Case Study | 25 | Techniques from Stoll's 1988 account of the LBL intrusion: default and guessed accounts, cracked password files, the movemail privilege escalation, dormant accounts and the... |
| The Dot-Com Era: Cyber Events, 1994 to 2003 | 36 | Techniques from the dot-com era record, 1994 to 2003: Melissa and Love Letter's mail-borne macros and scripts, CIH's disk and BIOS wipe, the exploited IIS, SQL Server and DCOM RPC... |
| The FireEye Mandiant Intrusion of 2020 | 41 | Techniques from the FireEye intrusion and the campaign that delivered it, from the trojanized Orion update and the second-phone MFA alert to forged SAML tokens, added cloud... |
| The Ransomware Ecosystem, 2019 to 2026 | 52 | Techniques from the 2019 to 2026 ransomware record, from VPNs without MFA, edge exploits and help-desk calls to RClone exfiltration, encryption and leak-site extortion. |
| The Ransomware Ecosystem, 2019 to 2026 (ICS) | 3 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. |
| The Trojanized Claude Code Extension on Cursor's Marketplace (October 2026) Case Study | 17 | Techniques from the tampered Claude Code extension that Cursor's marketplace served on 29 October 2026, from the marketplace upload and the loader in extension.js to host... |
| The Year 1993 in Intrusions | 17 | Techniques from the dated 1993 record: the Internet Security Scanner CERT warned about, default accounts and password guessing, the sendmail, gopher and FTP server flaws CERT said... |
| The Year 1994 in Intrusions | 19 | Techniques from the dated 1994 record: the sniffer wave and its captured passwords, Trojaned system binaries and two back-doored source releases, the root exploits in the year's... |
| The Year 1995 in Intrusions | 18 | Techniques from the dated 1995 record: IP spoofing and the hijacked sessions of CA-95:01, SATAN and the December wave of automated scanning, the year's remote and local root... |
| The Year 1996 in Intrusions | 20 | Techniques from the dated 1996 record: the year's floods (UDP packet storms, SYN flooding and the oversized ping), phf and the CGI interpreters on public web servers, hostile Java... |
| The Year 1997 in Intrusions | 22 | Techniques from the dated 1997 record: the automated scans for the IMAP and POP flaw, remote root through sendmail, INN, talkd and statd, the set-uid local root advisories, the... |
| The Year 1998 in Intrusions | 29 | Techniques from the dated 1998 record: smurf reflection floods and the BSD stack crashes, the IRIX default-account sweeps, mscan and the scripted mountd attacks, the remote root... |
| The Year 1999 in Intrusions | 36 | Techniques from the dated 1999 record: the trojaned TCP Wrappers and util-linux sources, Melissa, Happy99, ExploreZip and CIH, the scripted RPC exploits and distributed sniffers... |
| The Year 2000 in Intrusions | 31 | Techniques from the dated 2000 record: Stacheldraht, Windows trinoo and mstream agent pools, nameserver amplification and the February floods, the BIND, wu-ftpd, rpc.statd, IRIX... |
| The Year 2000 in Intrusions (ICS) | 12 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. |
| The Year 2001 in Intrusions | 27 | Techniques from the dated 2001 record: the ramen toolkit, the BIND kits and snmpXdmid with Carko, sadmind/IIS, Code Red's scanning, defacement and flood, Code Red II's back door... |
| The Year 2002 in Intrusions | 27 | Techniques from the dated 2002 record: the trojaned OpenSSH, Sendmail and tcpdump/libpcap source distributions, the exploited dtspcd flaw, Slapper and Scalper against Apache... |
| The Year 2003 in Intrusions | 35 | Techniques from the dated 2003 record: Slammer and the exploited IIS WebDAV flaw, the weak-password SMB compromises and their IRC-commanded bots, the public DCOM RPC exploits... |
| The Year 2003 in Intrusions (ICS) | 2 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. |
| The Year 2004 in Intrusions | 22 | Techniques from the dated 2004 record: the Bagle, MyDoom and Netsky mass mailers and Phatbot, Witty's single-packet exploit and disk wipe against ISS security software, Sasser... |
| The Year 2005 in Intrusions | 31 | Techniques from the dated 2005 record: CardSystems' SQL injection and scheduled exfiltration of card data, default credentials and open wireless at BJ's and DSW, misused customer... |
| The Year 2006 in Intrusions | 20 | Techniques from the dated 2006 record: the Windows Metafile, Internet Explorer, Word, Excel, PowerPoint, VML and WebViewFolderIcon flaws exploited at release, the Server service... |
| The Year 2007 in Intrusions | 17 | Techniques from the dated 2007 record: the Storm Worm's e-mail dropper, peer-located second stage and floods, the Word, Excel, animated cursor and DNS Server RPC flaws exploited... |
| The Year 2007 in Intrusions (ICS) | 2 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. |
| The Year 2008 in Intrusions | 33 | Techniques from the dated 2008 record: MS08-067 and the Conficker worm, Agent.btz and Fanny on removable media, the SQL injection wave and drive-by forwarding, the exploited... |
| The Year 2009 in Intrusions | 60 | Techniques from the dated 2009 record: Conficker through MS08-067, thumb drives and network shares with its domain generation and the coalition that disrupted it, the Adobe... |
| The Year 2010 in Intrusions | 71 | Techniques from the dated 2010 record: Elderwood and Hydraq for Operation Aurora with ATT&CK's own caveats, the Night Dragon campaign against energy companies, Stuxnet's USB... |
| The Year 2010 in Intrusions (ICS) | 10 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. |
| The Year 2011 in Intrusions | 66 | Techniques from the dated 2011 record: the Night Dragon campaign against energy companies, Duqu's signed driver, kernel zero-day and staged collection, APT1's techniques for its... |
| The Year 2012 in Intrusions | 36 | Techniques from the dated 2012 record: Flame's removable-media spread, collection and Bluetooth exfiltration, Shamoon's disk wipe from the 2012 report, Elderwood's watering holes... |
| The Year 2013 in Intrusions | 60 | Techniques from the dated 2013 record: APT1's tradecraft from Mandiant's February report, Winnti's supply-chain trojan and stolen certificates, Kimsuky's and NetTraveler's... |
| The Year 2014 in Intrusions | 45 | Techniques from the dated 2014 record: Shellshock and the Drupal SQL injection on public-facing servers, the Kerberos and Group Policy Preferences flaws under targeted attack, CCS... |
| The Year 2014 in Intrusions (ICS) | 14 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. |
| The Year 2015 in Intrusions | 57 | Techniques from the dated 2015 record: the Ukrainian blackout campaign C0028 with its VPN access, valid credentials and KillDisk wipe, Equation's disk firmware, the Hacking Team... |
| The Year 2015 in Intrusions (ICS) | 20 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. |
| The Year 2016 in Intrusions | 63 | Techniques from the dated 2016 record: APT28's credential phishing and the DNC intrusions, Shamoon 2's wiper, the Bangladesh Bank SWIFT theft, SamSam and Locky ransomware, Mirai's... |
| The Year 2016 in Intrusions (ICS) | 22 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. 3 ids not in the bundled data (library-sync.json). |
| The Year 2017 in Intrusions | 68 | Techniques from the dated 2017 record: the WannaCry, NotPetya and Bad Rabbit worms, the M.E.Doc, NetSarang and CCleaner update compromises, the service-provider and Dragonfly... |
| The Year 2017 in Intrusions (ICS) | 28 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. 3 ids not in the bundled data (library-sync.json). |
| The Year 2018 in Intrusions | 127 | Techniques from the dated 2018 record: Olympic Destroyer's wiper, VPNFilter and the Russian router and switch campaign, Dragonfly's forced authentication and staging targets... |
| The Year 2018 in Intrusions (ICS) | 4 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. |
| The Year 2019 in Intrusions | 82 | Techniques from the 2019 record, from edge-device exploitation and big game hunting ransomware to DNS hijacking, supply-chain compromise and cloud data theft. |
| The Year 2020 in Intrusions Case Study | 104 | Techniques from the 2020 record: edge-device exploitation, password spraying, the SolarWinds supply chain, and the Ryuk, Maze and WastedLocker ransomware intrusions. |
| The Year 2020 in Intrusions ICS | 9 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. |
| The Year 2021 in Intrusions | 93 | Techniques from the dated 2021 record: edge-device exploitation, NOBELIUM phishing and identity abuse, APT40 tradecraft, and the DarkSide, Conti, BlackMatter and REvil ransomware... |
| The Year 2021 in Intrusions (ICS) | 3 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. |
| The Year 2022 in Intrusions | 116 | Techniques from the dated 2022 record: the wipers and the satellite-modem attack of the war in Ukraine, LAPSUS$ and the SMS phishing against help desks and staff, MFA request... |
| The Year 2022 in Intrusions (ICS) | 17 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. 2 ids not in the bundled data (library-sync.json). |
| The Year 2023 in Intrusions | 123 | Techniques from the dated 2023 record: the exploited edge appliances and file-transfer servers, web shells, forged tokens and stolen session cookies, help-desk voice phishing and... |
| The Year 2023 in Intrusions (ICS) | 12 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. |
| The Year 2024 in Intrusions | 68 | Techniques from the dated 2024 record: the exploited edge appliances (Ivanti, PAN-OS, FortiManager, ScreenConnect), Volt Typhoon's living off the land, Midnight Blizzard's... |
| The Year 2025 in Intrusions | 122 | Techniques from the dated 2025 record: the exploited edge appliances and servers, web shells, stolen OAuth tokens and connected-app abuse, help-desk voice phishing, compromised... |
| The Year 2025 in Intrusions (ICS) | 3 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. |
| The Year 2026 in Intrusions | 125 | Techniques from the dated 2026 record: the Trivy, LiteLLM and axios supply-chain compromises, the exploited edge appliances (Cisco SD-WAN, PAN-OS, Citrix, Ivanti, BeyondTrust)... 1 id not in the bundled data (library-sync.json). |
| The Year 2026 in Intrusions (ICS) | 17 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. |
| The Zero-Day Trade and Its Fallout | 75 | Techniques behind the zero-day trade's fallout: Operation Aurora's drive-by and spearphishing entry, the Equation and Hacking Team firmware persistence, and the SMB worm spread... |
| The Zero-Day Trade and Its Fallout (ICS) | 5 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. |
| Thirty Days of Exposure Checks (KEV, October to November 2026) Case Study | 12 | Techniques from a month of KEV listings checked in the lab: public-facing exploitation, privilege escalation, web shells, the Mark-of-the-Web bypass and the follow-on mining. |

### Threat actors (synced)

| Layer | Techniques | Notes |
|---|---|---|
| China-Attributed Threat Actors Case Study | 77 | Techniques from the public record on China-attributed threat actors: the ids named in six joint government advisories on APT40, Volt Typhoon, Salt Typhoon and PRC network-device... |
| Healthcare Threat Actor Watchlist 2023-2026 | 130 | Techniques named in the joint advisories on the ransomware and state actors that hit healthcare from 2023 to 2026, scored by how many advisories name each one. |
| Iran-Attributed Threat Actors Case Study | 260 | The tradecraft of the Iran-attributed groups and the joint advisories on them, led by public-tool use, PowerShell, credential dumping, scheduled tasks and the exploitation of... 1 id not in the bundled data (library-sync.json). |
| Iran-Attributed Threat Actors Case Study (ICS) | 24 | Curated case-study layer, not an official MITRE mapping. ICS ATT&CK layer. 2 ids not in the bundled data (library-sync.json). |
| North Korea-attributed threat actors | 251 | The ATT&CK records of the eight North Korea-attributed groups, from Lazarus Group to Contagious Interview, plus the techniques only the US and allied advisories state (AA23-040A... |
| Other state-linked threat actors | 154 | The document-and-lure tradecraft of the state-linked tier outside the five largest programs: South Asian, Vietnamese, Lebanese, Gulf, Gaza, Turkish and Belarus-aligned groups... |
| Russia-Attributed Threat Actors Case Study | 332 | Techniques from the public record on Russia-attributed threat actors: what ATT&CK records for nine groups tied to the GRU, SVR, FSB and TsNIIKhM and their campaigns, plus the ids... |
| United States-Attributed Threat Actors Case Study | 86 | The tradecraft ATT&CK records for the toolsets most often linked to the United States in the public record (Equation, Regin, Duqu, Flame, Stuxnet and Green Lambert), heavy on... |

### Vendors (synced)

| Layer | Techniques | Notes |
|---|---|---|
| Cloud Security Coverage: Wiz, Prisma Cloud, Microsoft Defender for Cloud | 25 | ATT&CK technique coverage provided by Wiz, Prisma Cloud (Palo Alto Networks), and Microsoft Defender for Cloud through CSPM, secrets scanning, cloud account protection, and... |
| EDR: CrowdStrike Falcon / SentinelOne / Carbon Black | 25 | Endpoint Detection and Response coverage: process execution monitoring, memory scanning, behavioral ML, rollback capabilities. |
| Email Security: Proofpoint / Mimecast / Microsoft Defender for O365 | 24 | Secure email gateway, sandboxing, DMARC enforcement, click-time URL protection, anti-phishing and BEC coverage. |
| Email Security: Proofpoint + Mimecast | 13 | ATT&CK technique coverage for email security vendors Proofpoint and Mimecast. |
| Identity & PAM: Entra ID + Okta + CyberArk | 25 | ATT&CK technique coverage for identity and privileged access management vendors: Microsoft Entra ID, Okta, and CyberArk. |
| Identity: Okta / Microsoft Entra ID / CyberArk PAM | 24 | Identity Provider, MFA, Conditional Access, Privileged Access Management, and UEBA coverage. |
| Network & Zero Trust: Zscaler + Palo Alto NGFW | 20 | ATT&CK technique coverage for network security and Zero Trust vendors: Zscaler Zero Trust Exchange and Palo Alto Networks NGFW. |
| Network Security: Palo Alto NGFW / Fortinet FortiGate / Cisco Secure | 24 | Next-generation firewall, IDS/IPS, SSL decryption, DNS security, and network segmentation coverage. |
| SIEM Coverage: Splunk ES, Microsoft Sentinel, Elastic Security | 31 | ATT&CK technique coverage provided by Splunk Enterprise Security, Microsoft Sentinel, and Elastic Security SIEM through log correlation, behavioral detection rules, and UEBA... |
| Vulnerability Management: Tenable + Qualys + Wiz | 15 | ATT&CK technique coverage for vulnerability management and CSPM vendors: Tenable, Qualys, and Wiz. |
| WAF/WAAP: Cloudflare / Akamai / AWS WAF / F5 Advanced | 24 | Web Application Firewall and API protection coverage: SQLi/XSS/SSRF/RCE blocking, rate limiting, bot management, DDoS mitigation. |

### Kill-chain stages (synced)

| Layer | Techniques | Notes |
|---|---|---|
| Application Security (cross-stage view) | 26 | SAST, DAST, SCA, WAF, API security, DevSecOps pipeline controls. |
| Identity & Access Management (alternate view of Stage 2) | 31 | IAM, PAM, MFA, SSO, Conditional Access, JIT access controls. |
| Network & Perimeter Security (alternate view of Stage 4) | 25 | NGFW, IDS/IPS, NDR, DNS security, network segmentation controls. |
| Stage 1: Governance, Risk & Compliance | 17 | ATT&CK technique coverage from Stage 1: Governance, Risk & Compliance controls (NIST 800-53 PM/PL/CA/RA/SA families). |
| Stage 2: Identity & Access Management | 20 | ATT&CK technique coverage for Pipeline Stage 2: Identity & Access Management. |
| Stage 3: Endpoint & Workload Protection | 21 | ATT&CK technique coverage from Stage 3: Endpoint & Workload Protection (EDR, AV, HIPS, application control). |
| Stage 4: Network & Boundary Defense | 24 | ATT&CK technique coverage for Pipeline Stage 4: Network & Boundary Defense. |
| Stage 5: Visibility, Detection & Operations | 25 | ATT&CK technique coverage for Pipeline Stage 5: Visibility, Detection & Operations. |
| Stage 6: Data & Cloud Security | 20 | ATT&CK technique coverage from Stage 6: Data & Cloud Security (DSPM, CSPM, DLP, CASB, encryption). |

### Computed (synced)

| Layer | Techniques | Notes |
|---|---|---|
| D3FEND Blind Spots | 383 | Rule: A live ATT&CK Enterprise technique is in the layer when data/attack/technique_to_d3fend.jsonl has no row for its ID or for an ID it replaced... 9 ids not in the bundled data (library-sync.json). |
| Detection Strategy Gaps | 3 | Rule: A live ATT&CK Enterprise technique is in the layer when ATT&CK publishes no detection strategy for it (has_detection_strategy is false in... 3 ids not in the bundled data (library-sync.json). |
| Mapping Completeness | 706 | Rule: Every live ATT&CK Enterprise technique is in the layer; the score counts which of five library mappings it has (0 to 5): an ATT&CK mitigation, a NIST SP 800-53 control, a... 9 ids not in the bundled data (library-sync.json). |
| NIST 800-53 R5 Control Depth | 466 | The 466 live ATT&CK Enterprise v20.0 techniques with at least one NIST 800-53 R5 control mapping, scored by control depth: the number of distinct NIST controls that map to the... |
| Platform Exposure | 706 | Rule: Every live ATT&CK Enterprise technique is in the layer; the score is the number of ATT&CK platforms the technique lists. 9 ids not in the bundled data (library-sync.json). |
| Ransomware Family Techniques | 186 | Rule: A live ATT&CK Enterprise technique is in the layer when at least one ATT&CK software entry whose description's first sentence contains the word "ransomware" uses it; the... |

### Analytics (synced)

| Layer | Techniques | Notes |
|---|---|---|
| ATT&CK Framework Blind Spots - No NIST 800-53 Coverage | 240 | The 240 live ATT&CK Enterprise v20.0 techniques with NO mapped NIST 800-53 R5 control (CTID), under their own id or a revoked predecessor's. 9 ids not in the bundled data (library-sync.json). |
| ATT&CK Technique Frequency - Threat Group Usage | 515 | The 515 ATT&CK Enterprise v20.0 techniques used by at least one tracked threat group, colored by the number of groups observed using them. 1 id not in the bundled data (library-sync.json). |
| ICS ATT&CK - Threat Group Frequency | 28 | The 28 MITRE ATT&CK for ICS techniques used by at least one tracked threat group, colored by the number of groups using them. ICS ATT&CK layer. 3 ids not in the bundled data (library-sync.json). |
| Mobile ATT&CK - Threat Group Frequency | 24 | The 24 MITRE ATT&CK for Mobile techniques used by at least one tracked threat group, colored by the number of groups using them. Mobile ATT&CK layer. 1 id not in the bundled data (library-sync.json). |

### AI (synced)

| Layer | Techniques | Notes |
|---|---|---|
| ATLAS Case Study Frequency | 221 | Heatmap of technique occurrences in 77 ATLAS case studies. ATLAS layer: no bundled matrix renders it. |
| ATLAS Matrix | 221 | Adversarial Threat Landscape for Artificial-Intelligence Systems, see atlas.mitre.org. ATLAS layer: no bundled matrix renders it. |
| Hugging Face AI Supply Chain (ATLAS) | 42 | ATLAS 2026.10 techniques that MITRE maps in the five Hugging Face case studies (AML.CS0019, AML.CS0027, AML.CS0031, AML.CS0065, AML.CS0068, all 37 CS0068 steps) plus the adjacent... ATLAS layer: no bundled matrix renders it. |

### Fraud (synced)

| Layer | Techniques | Notes |
|---|---|---|
| F3 Matrix | 123 | Knowledge base of tactics, techniques, and procedures used by financial fraud actors, see ctid.mitre.org/fraud. F3 fraud layer. 1 id not in the bundled data (library-sync.json). |

9 library layers were not added because a layer with the same name or the same rows is already listed; library-sync.json names each one and the copy kept.

<!-- library-sync:end -->

## Analyst use-cases

- **Detection-gap analysis** - overlay a control/theme layer against your own coverage layer to find unmapped techniques.
- **Adversary emulation & purple teaming** - load a threat-group layer to scope an emulation plan or a tabletop around what that actor actually does.
- **Prioritization** - the HTB frequency and agentic-swarm layers highlight techniques that recur, useful for sequencing detection or hardening work.
- **Comparison** - switch between two group layers to see shared vs distinctive TTPs, or a group vs a theme to map an actor onto a weakness class.

## Adding a new layer

Layers are **data-only** at runtime. The approved program architecture makes the companion library the canonical source for all layers.

**A layer the library publishes** needs no hand work here: add it to the library, then run `node scripts/sync-library-layers.mjs`. It pulls the library's published index and every file it names, plus the other folders under `navigator/` (case-studies, vendors, stages, computed, analytics, ai, fraud and the loose files at the top), validates each file as a Navigator layer, skips duplicates (same name as a layer already listed, or the same rows; the published-set copy wins, a bundled layer wins over both), checks every technique id against the bundled ATT&CK data, and writes the files under group prefixes (`study-`, `actor-`, `vendor-`, `stage-`, `computed-`, `analytics-`, `ai-`, `fraud-`), the manifest entries (each with `group` and `source`), the lock file `library-sync.json` (synced date, source index sha256, and each file's source address, sha256 and unresolved ids) and the generated section of this guide. A layer naming an id the bundled data does not know is kept whole; the id is recorded in the lock. `node scripts/sync-library-layers.mjs --check` (in CI) verifies offline that every synced file matches the lock, that the manifest lists every file exactly once, that the recorded unresolved ids still match the bundled data and that this guide is current; `--docs` rewrites the generated section from the manifest and lock without the network; `--report FILE` writes the counts, duplicates and unresolved ids as Markdown. The monthly data refresh runs the sync too, so new library layers arrive in its pull request.

**A layer bundled only in this repository** follows the workbench ingestion contract:

1. Drop a MITRE Navigator v4.5 layer JSON into `src/assets/data/library-layers/` (`domain: enterprise-attack`, a `techniques[]` array of `{ techniqueID, tactic, score, comment }`).
2. Add an entry to `index.json` after the last bundled entry (bundled entries come before the synced ones) with `file`, `name`, `description`, `blurb` and `group` (one of the bundled groups), and no `source`.
3. Ensure every `techniqueID` and tactic resolves in the bundled `enterprise-attack.json`; preserve cohort, method, version, and normalization metadata. No component change is needed just to list the layer: the picker enumerates the manifest at runtime.
4. Run `node scripts/validate-curated-threat-layers.mjs` (it checks every manifest layer and the vendored Lylat layers against the bundled snapshots, and the layer counts in this guide) and the relevant tests. Reconcile this guide with all manifest entries, counting unique IDs rather than tactic-expanded rows. Keep deterministic generators alongside their outputs in the canonical source; do not commit private source material or locators.

