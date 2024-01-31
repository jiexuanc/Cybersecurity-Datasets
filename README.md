# Cybersecurity-Datasets
Overview:

Collection of cybersecurity datasets for intrusion detection, separated by the type of data (network, event logs, verbose). Note that there are major overlaps between the type of data and the separation is only done for my sanity. Network files and verbose logs are plentiful. Event logs not so much...

Network (i.e. PCAPs, DNS)
---
- [CICIDS2017](https://www.kaggle.com/datasets/cicdataset/cicids2017/data)
    - Paper: https://www.scitepress.org/papers/2018/66398/66398.pdf
    - CICIDS2017 dataset contains benign and the most up-to-date common attacks, which resembles the true real-world data (PCAPs)
    - Included the most common attacks based on the 2016 McAfee report, such as Web-based, Brute force, DoS, DDoS, Infiltration, Heart-bleed, Bot, and Scan covered in this dataset.
- 
- 
- [DARPA 1999](https://www.ll.mit.edu/r-d/datasets/1999-darpa-intrusion-detection-evaluation-dataset)
    - Really quite dated...

Event Logs 
---
- [**DARPA OpTC**](https://ieee-dataport.org/open-access/operationally-transparent-cyber-optc)
    - Paper: https://arxiv.org/abs/2103.03080
    - Alternative link for individual logs: https://github.com/FiveDirections/OpTC-data
    - The experiment testbed consisted of 1000 hosts with Windows 10 operating system. Dataset contains benign, evaluation and short folders
        - Benign stores the normal activity captured
        - Evaluation stores event captured during the red team activity period
        - Short contains events that were captured but is missing values

- [**Unified Host and Network Data Set (LANL 2018)**](https://csr.lanl.gov/data/2017)
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

Verbose
---
- [Loghub](https://github.com/logpai/loghub)
    - Supercomputers (BGL and Thunderbird)
    - Hadoop distributed file system log
- Common crawl is a possible option if looking for random application logs (But cannot expect how labelling is possible)
- [NGINX Web Server Access Logs](https://www.kaggle.com/datasets/eliasdabbas/web-server-access-logs)
    - Paper: https://doi.org/10.7910/DVN/3QBYB5


Require Access
---
- [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- [Four Labeled Datasets to Enable Reproducible Cyber Research](https://cybervan.peratonlabs.com:9000/milcom-2016-data-sets)
- [What Supercomputers Say: A Study of Five System Logs](https://www.semanticscholar.org/paper/What-Supercomputers-Say%3A-A-Study-of-Five-System-Oliner-Stearley/01b5c01835a57f63c250b4eed923b7f736707624)

Public dataset collections
---
- [AZSecure-data](https://www.azsecure-data.org/other-data.html)
- [SecRepo](https://www.secrepo.com/)
- [Real-CyberSecurity-Datasets](https://github.com/gfek/Real-CyberSecurity-Datasets)

Issues faced
---
Challenges faced acquiring host log data are best described by [Reproducible and Adaptable Log Data Generation for Sound Cybersecurity Experiment](https://arxiv.org/pdf/2111.07847.pdf)
- Required for the application of SIGMA detection rules, and that these data to be sufficiently detailed
- Collection in a production network with real users provide realistic data but confidentiality and privacy issue forbid the publication of these data
    - OS (Windows/MacOS/Linux) logs are usually not publicly available
    - Even publicly available logs have extensive anonymization and are of little use (Refer to Windows Audit Log)
- Rely on dedicated lab testbeds for log data acquisition
    - Does not capture real enterprise usage with less focus on benign cases
    - Tends to be of a smaller scale
- End result is that researchers often create their own testbed or work with enterprises for their host log data generation
- DARPA OpTC and LANL 2018 allievate some of the issues...

Interesting stuff
---
[SSADLog: Whole Lifecycle Tuning Anomaly Detection with Small Sample Logs](https://github.com/NickZhouSZ/SSADLog)
- SSADLog introduces a hyper-efficient log data pre-processing method that generates a representative subset of small sample logs. It leverages a pre-trained bidirectional encoder representations from transformers (BERT) language model to create contextual word embeddings. Furthermore, a semi-supervised fine-tuning process is employed for enhancing detection accuracy. A distinctive feature of SSADLog is its ability to fine-tune language models with small samples, achieving high-performance iterations in just approximately 30 minutes.
- During training phase, queue based eliminating duplication for initial training, then PLHF + Tuning purposed balancing = Fine Tuning Log Messages for fine tuning
- During operations, same finetuning process is done without initial training (This step is quite mysterious as during operations, log messages wouldn't be labelled)
- Dataset used: BGL and Thunderbird (Both present in Loghub and labelled), Spirit1G (require access), real-world dataset (Not disclosed)

[NODOZE: Combatting Threat Alert Fatigue with Automated Provenance Triage](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_03B-1-3_UlHassan_paper.pdf)
- Discuss the limitations of existing threat detection softwares
    - Require analyst to construct dependency graph (control/data) forward and backward at sufficient depth (data provenance) to investigate the potential attack --> Dependency explosion especially with long running processes
    - Possibly thousands of false alerts with only a couple true alerts, looking for a needle in haystack
- Combatting threat alert via construction of dependency graph and finding the most anomalous subgraph
    - Anomality score is not based on a single event, rather based on the whole graph
    
Looking into alert correlations...
- [**A New Alert Correlation Model Based On Similarity Approach**](https://ieeexplore.ieee.org/document/8874899) 
- [An Intrusion Action-Based IDS Alert Correlation Analysis and Prediction Framework](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8862902)
- [Comprehensive Approach to Intrusion Detection Alert Correlation](https://sites.cs.ucsb.edu/~vigna/publications/2004_valeur_vigna_kruegel_kemmerer_TDSC_Correlation.pdf)
- [Alert Correlation Algorithms: A Survey and Taxonomy](https://arxiv.org/ftp/arxiv/papers/1811/1811.00921.pdf)

