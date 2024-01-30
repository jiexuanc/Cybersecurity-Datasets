# Cybersecurity-Datasets
Overview:

Collection of cybersecurity datasets for intrusion detection, separated by the type of data (network, event logs, verbose):

Network (i.e. PCAPs, DNS)
- Log
-
-
-
-
-

Event Logs 
- DARPA OpTC -- 18B events (~300 GB zipped)
    - Paper: https://arxiv.org/abs/2103.03080
    - Dataset: https://ieee-dataport.org/open-access/operationally-transparent-cyber-optc
    - The experiment testbed consisted of 1000 hosts with Windows 10 operating system. Dataset contains benign, evaluation and short folders
        - Benign stores the normal activity captured
        - Evaluation stores event captured during the red team activity period
        - Short contains events that were captured but is missing values

- LANL 2015 & 2018
    - https://csr.lanl.gov/data/2017/
    - https://csr.lanl.gov/datassss/cyber1/
- Malicious Behavior Detection using Windows Audit Logs 
    - Paper: https://arxiv.org/pdf/1506.04200.pdf
    - Dataset: https://github.com/konstantinberlin/malware-windows-audit-log-detection
    - Extensive anonymization of dataset, unable to apply rule detection

Note that many event logs datasets also contain network data

Observations:
Network files and verbose logs are plentiful.
Event logs are a tragedy. (This is where SIGMA rules are applied)

Problems:
Best described by this paper on the challenges of acquiring log data -> https://arxiv.org/pdf/2111.07847.pdf
- Collection in a production network with real users provide realistic data but confidentiality and privacy issue forbid the publication of these data
    - OS (Windows/MacOS/Linux) logs are usually not publicly available
    - Even publicly available logs have extensive anonymization and are of little use (Refer to Windows Audit Log)
- Rely on dedicated lab testbeds for log data acquisition
    - Small-scale datasets focus only on attack scenarios 
    - 
- DARPA OpTC might solve many of the above problems but I have yet to see the data, 300GB is huge...

End result is that researchers often create their own testbed or work with enterprises for their data generation
- 
- 
