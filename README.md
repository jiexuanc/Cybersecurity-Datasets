# Cybersecurity-Datasets
Overview:

Collection of cybersecurity datasets for intrusion detection, separated by the type of data (network, event logs, verbose):

Network (i.e. PCAPs, DNS)
---
- [CICIDS2017](https://www.kaggle.com/datasets/cicdataset/cicids2017/data)
    - Paper: https://www.scitepress.org/papers/2018/66398/66398.pdf
-
-
-
-

Event Logs 
---
- [DARPA OpTC](https://ieee-dataport.org/open-access/operationally-transparent-cyber-optc) -- 18B events (~300 GB zipped)
    - Paper: https://arxiv.org/abs/2103.03080
    - Alternative link for individual logs: https://github.com/FiveDirections/OpTC-data
    - The experiment testbed consisted of 1000 hosts with Windows 10 operating system. Dataset contains benign, evaluation and short folders
        - Benign stores the normal activity captured
        - Evaluation stores event captured during the red team activity period
        - Short contains events that were captured but is missing values

- [Unified Host and Network Data Set (LANL 2018)](https://csr.lanl.gov/data/2017)
    - The host event logs originated from most enterprise computers running the Microsoft Windows operating system on Los Alamos National Laboratory’s (LANL) enterprise network. The network event data originated from many of the internal enterprise routers within the LANL enterprise network.
    - Does not have any documented red team activities which severely compromises its utility in advanced persistent threat detection

- [Comprehensive, Multi-Source Cyber-Security Events (LANL 2015)](https://csr.lanl.gov/data/cyber1/)
    - The data sources include Windows-based authentication events from both individual computers and centralized Active Directory domain controller servers; process start and stop events from individual Windows computers; Domain Name Service (DNS) lookups as collected on internal DNS servers; network flow data as collected on at several key router locations; and a set of well-defined red teaming events that present bad behavior within the 58 days.
    - Only tags login events with nominal red team labeling

- [Malicious Behavior Detection using Windows Audit Logs](https://github.com/konstantinberlin/malware-windows-audit-log-detection)
    - Paper: https://arxiv.org/pdf/1506.04200.pdf
    - Extensive anonymization of dataset
- Indicator of compromise (IOCs)
    - [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack)
    - [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
    - [Security-Datasets](https://github.com/OTRF/Security-Datasets)

Note that many event logs datasets also contain network data

Verbose
---
- [Loghub](https://github.com/logpai/loghub)
    - Supercomputers (BGL and Thunderbird)
    - Hadoop distributed file system log
- Common crawl is a possible option if looking for random application logs (But cannot expect any form of labelled data)

Require Access
---
- [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- [Four Labeled Datasets to Enable Reproducible Cyber Research](https://cybervan.peratonlabs.com:9000/milcom-2016-data-sets)
- [What Supercomputers Say: A Study of Five System Logs](https://www.semanticscholar.org/paper/What-Supercomputers-Say%3A-A-Study-of-Five-System-Oliner-Stearley/01b5c01835a57f63c250b4eed923b7f736707624)

Observations:
Network files and verbose logs are plentiful.
Event logs not so much...

Issues faced
---

Challenges faced acquiring host log data are best described by this [paper](https://arxiv.org/pdf/2111.07847.pdf)
- Required for the application of SIGMA detection rules, and that these data to be sufficiently detailed
- Collection in a production network with real users provide realistic data but confidentiality and privacy issue forbid the publication of these data
    - OS (Windows/MacOS/Linux) logs are usually not publicly available
    - Even publicly available logs have extensive anonymization and are of little use (Refer to Windows Audit Log)
- Rely on dedicated lab testbeds for log data acquisition
    - Does not capture real enterprise usage
    - Less focus on benign cases
- End result is that researchers often create their own testbed or work with enterprises for their host log data generation
- DARPA OpTC and LANL 2018 allievate some of the issues...

Interesting stuff
---
[SSADLog: Whole Lifecycle Tuning Anomaly Detection with Small Sample Logs](https://github.com/NickZhouSZ/SSADLog)
- SSADLog introduces a hyper-efficient log data pre-processing method that generates a representative subset of small sample logs. It leverages a pre-trained bidirectional encoder representations from transformers (BERT) language model to create contextual word embeddings. Furthermore, a semi-supervised fine-tuning process is employed for enhancing detection accuracy. A distinctive feature of SSADLog is its ability to fine-tune language models with small samples, achieving high-performance iterations in just approximately 30 minutes.
- During training phase, queue based eliminating duplication for initial training, then PLHF + Tuning purposed balancing = Fine Tuning Log Messages for fine tuning
- During operations, same finetuning process is done without initial training (This is quite mysterious as during operations, log messages wouldn't normally be labelled)
- Dataset used: BGL and Thunderbird (Both present in Loghub and labelled), Spirit1G (require access), real-world dataset (Not disclosed)
