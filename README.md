# Trip Through Your Wires - An Attacker's Hazardous Journey

This repository contains the ATT&CK Navigator matrices for the threats discussed in [Breakout BRKSEC-3026 "Trip Through Your Wires - An Attacker's Hazardous Journey"](https://www.ciscolive.com/global/learn/session-catalog.html?search=BRKSEC-3026#/). This session is being delivered at Cisco Live US in San Diego June 12th, 2025, and focuses on the evolution of APT29 (Cozy Bear, The Dukes, Midnight Blizzard, or Nobelium, among other names).

It includes a top-level JSON that will pre-populate all of the component JSONs in 1 action. This will also include more source JSONs and the example YAML files for DeTTECT.

## Related Tools
I am also using some additional tools in the presentation that can be obtained via the following repos:
- [MITRE ATT&CK's Homepage](https://attack.mitre.org)
- [ATT&CK Parser](https://github.com/mjmcphee/attack_parser)
- [ATT&CK Rosetta](https://github.com/mjmcphee/attack-rosetta)
- [MITRE ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator)
- [MITRE ATT&CK STIX Data](https://github.com/mitre-attack/attack-stix-data) - for when the TAXII server is down.
- [MITRE CTID's Threat Emulation Library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library)

## To use:
Clone the repo as needed for ready access to the examples worked on in BRKSEC-3026.

Specific instructions for the Related Tools are offered in each repository.

## APT29's Eras (covered in this talk)
- [BBC's SVR Profile (the non Cyber aspects, useful history)](https://www.bbc.com/news/10447308)
- [F-Secure's Whitepaper on APT29's "Dukes" Legacy: THE DUKES - 7 YEARS OF RUSSIAN CYBERESPIONAGE](https://blog-assets.f-secure.com/wp-content/uploads/2020/03/18122307/F-Secure_Dukes_Whitepaper.pdf)
- [UK Government's blog on Russia's FSB malign activity: factsheet](https://www.gov.uk/government/publications/russias-fsb-malign-cyber-activity-factsheet/russias-fsb-malign-activity-factsheet)
- [Picus Security: APT29 Explained: Cozy Bear's Evolution, Techniques, and Notorious Cyber Attacks](https://www.picussecurity.com/resource/blog/apt29-cozy-bear-evolution-techniques)


### SolarWinds Supply Chain Breach 2019-2021
- [SolarWinds Security Advisory](https://www.solarwinds.com/sa-overview/securityadvisory)
- [Supply Chain Compromise](https://www.cisa.gov/news-events/alerts/2021/01/07/supply-chain-compromise)
- [Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims With SUNBURST Backdoor](https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor)
- [The SolarWinds cyberattack: The hack, the victims, and what we know](https://www.bleepingcomputer.com/news/security/the-solarwinds-cyberattack-the-hack-the-victims-and-what-we-know/)
- [Analyzing Solorigate, the compromised DLL file that started a sophisticated cyberattack, and how Microsoft Defender helps protect customers](https://www.microsoft.com/en-us/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/)
- [Deep dive into the Solorigate second-stage activation: From SUNBURST to TEARDROP and Raindrop](https://www.microsoft.com/en-us/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/)
- [SUNSPOT: An Implant in the Build Process](https://www.crowdstrike.com/en-us/blog/sunspot-malware-technical-analysis/)
- [Early Bird Catches the Wormhole: Observations from the StellarParticle Campaign](https://www.crowdstrike.com/en-us/blog/observations-from-the-stellarparticle-campaign/)

- [List of DGA FQDNs culled by John Bambenek for tracking SUNBURST C2 domains](https://github.com/bambenek/research/blob/main/sunburst/uniq-hostnames.txt)

###  Cloud Tenant Attacks 2022-2024
- [Russian APT29 hackers' stealthy malware undetected for years](https://www.bleepingcomputer.com/news/security/russian-apt29-hackers-stealthy-malware-undetected-for-years/)
- [CISA: SVR Cyber Actors Adapt Tactics for Initial Cloud Access](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a)

### Diplomatic & Political Attacks 2023-Present
- [Renewed APT29 Phishing Campaign Against European Diplomats](https://research.checkpoint.com/2025/apt29-phishing-campaign/)
- [Backchannel Diplomacy: APT29’s Rapidly Evolving Diplomatic Phishing Operations](https://cloud.google.com/blog/topics/threat-intelligence/apt29-evolving-diplomatic-phishing)
- [APT29 Uses WINELOADER to Target German Political Parties](https://cloud.google.com/blog/topics/threat-intelligence/apt29-wineloader-german-political-parties)

## Other Resources

### Blogs and How-To's
- [MITRE’s own ATT&CK materials are hard to beat](https://attack.mitre.org)
- [Getting Started Guide – useful for all 4 use cases](https://attack.mitre.org/resources/getting-started/)
- [Best blog on Medium](https://medium.com/mitre-attack/)
- [Pyramid of Pain](https://globalsecuresolutions.com/the-pyramid-of-pain/)
- [Orbital for ATT&CK](https://blogs.cisco.com/security/finding-the-malicious-needle-in-your-endpoint-haystacks)
- [Threat Grid use of ATT&CK TTPs in reports: https://blogs.cisco.com/security/black-hat-usa-2018-attck-in-the-noc](https://github.com/user-attachments/assets/26f02cae-0b69-4326-8bf6-dba38a6abefa)

### Complimentary MITRE/CTID Efforts
- [Center for Threat-Informed Defense (CTID): group in MITRE Engenuity, leads ATT&CK, D3FEND, and related](https://ctid.mitre-engenuity.org)
- [D3FEND: counter ATT&CKs TTPs by detailing how one can harden, detect, isolate, deceive, or evict the threat](https://d3fend.mitre.org)
- [Cyber Analytics Repository (CAR): validated analytical recipes for tools like Splunk, Elastic, etc. help detect TTPs in use](https://car.mitre.org/)
- [ATT&CK Flow – a tool to assist in linking TTPs into an adversary’s behavior (alchemy ;) )](https://center-for-threat-informed-defense.github.io/attack-flow/)
- [ATT&CK Powered Suit: Browser plugin to link and research TTPs](https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/attack-powered-suit/)
- [Common Attack Pattern Enumeration and Classification (CAPEC): Like ATT&CK, but focused on applications](https://capec.mitre.org/)
- [Malware Attribute Enumeration and Characterization (MAEC)](http://maecproject.github.io/)
- [MITRE ENGAGE](https://engage.mitre.org/)

### Additional Software and Tools
- [MITRE’s ATT&CK Workbench: allows orgs to maintain a local repo of their own ATT&CK data and keep it in synch with global feeds](https://ctid.mitre-engenuity.org/our-work/attack-workbench/)
- [Red Canary’s Atomic Red Team](https://atomicredteam.io)
- [Sigma Project for easy conversion of analytics between SIEMs](https://github.com/SigmaHQ/sigma)
- [MITRE's D3FEND Project, useful for those designing defensive tools](https://d3fend.mitre.org/)
- [CVE2CAPEC tool, mapping CVEs to CWEs to TTPs](https://galeax.github.io/CVE2CAPEC/)
- [Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/)
- [CTID's CTI Blueprints](https://github.com/center-for-threat-informed-defense/cti-blueprints/wiki)
- [CTID's Sensor Mappings](https://center-for-threat-informed-defense.github.io/sensor-mappings-to-attack/levels/)
- [MISP (Malware Information Sharing Project)](https://www.misp-project.org/)
- [OpenCTI](https://filigran.io/solutions/open-cti/)

### CTI-related Resources
- [CIS Critical Security Controls, OS Benchmarks & Hardened Images a fantastic resource](https://www.cisecurity.org/cybersecurity-tools/)
- [OWASP Secure Software Development Lifecycle Project](https://www.owasp.org/index.php/OWASP_Secure_Software_Development_Lifecycle_Project)
- [UK National Cyber Security Centre](https://www.ncsc.gov.uk/section/advice-guidance/all-topics)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [US-CERT Resources](https://www.us-cert.gov/resources)
- [CREST Resource page](https://www.crest-approved.org/knowledge-sharing/index.html)
- [SANS Cyber Defense Reading Room](https://cyber-defense.sans.org/resources/whitepapers)
- [Awesome DeTTECT tutorial by Mohammed Alshaboti](https://medium.com/@alshaboti/getting-started-with-mitre-caldera-offensive-and-defensive-training-3ca9f693e0d7)

