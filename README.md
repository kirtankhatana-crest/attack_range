<p align="center">
    <a href="https://github.com/splunk/attack_range/releases">
        <img src="https://img.shields.io/github/v/release/splunk/attack_range" /></a>
    <a href="https://circleci.com/gh/splunk/attack_range/tree/develop">
        <img src="https://img.shields.io/circleci/build/github/splunk/attack_range?token=4ae763d7a7d21e86bb40a76797cab13cda402fba" /></a>
    <a href="https://github.com/splunk/attack_range/graphs/contributors" alt="Contributors">
        <img src="https://img.shields.io/github/contributors/splunk/attack_range" /></a>
    <a href="https://github.com/splunk/attack_range/stargazers">
        <img src="https://img.shields.io/github/stars/splunk/attack_range?style=social" /></a>
</p>

# Splunk Attack Range ⚔️
![Attack Range Log](docs/attack_range.png)

## Purpose 🛡
The Attack Range is a detection development platform, which solves three main challenges in detection engineering:
* **1.** The user is able to quickly build a small lab infrastructure as close as possible to a production environment.
* **2.** The Attack Range performs attack simulation using different engines such as Atomic Red Team or Caldera in order to generate real attack data. 
* **3.** It integrates seamlessly into any Continuous Integration / Continuous Delivery (CI/CD) pipeline to automate the detection rule testing process.  


## Demo 📺
[A short demo (< 3 min)](https://www.youtube.com/watch?v=yE7ytM3VNDQ) which shows the basic functions of the attack range. It builds a testing environment using terraform, walks through the data collected by Splunk. Then attacks it using MITRE ATT&CK Technique [T1003](https://attack.mitre.org/techniques/T1003/) and finally showcases how [Splunk Security Content](https://github.com/splunk/security-content) searches are used to detect the attack.

[![Attack Range Demo](https://img.youtube.com/vi/yE7ytM3VNDQ/1.jpg)](https://www.youtube.com/watch?v=yE7ytM3VNDQ)

## Building 👷‍♂️

Attack Range can be built in three different ways:

- [**cloud**](#installation) with terraform plus AWS or Azure.
- [**locally**](https://github.com/splunk/attack_range_local/) with vagrant and virtualbox
- [**serverless**](https://github.com/splunk/attack_range_cloud/) with terraform and AWS services

## Installation 🏗

### [Using Docker](https://github.com/splunk/attack_range/wiki/Using-Docker)

1. `docker pull splunk/attack_range`
2. `docker run -it splunk/attack_range`


### [AWS and Ubuntu 18.04](https://github.com/splunk/attack_range/wiki/AWS:-Ubuntu-18.04-Installation)

1. `source <(curl -s 'https://raw.githubusercontent.com/splunk/attack_range/develop/scripts/ubuntu_deploy.sh')`
2. `aws configure`
3. `python attack_range.py configure`

### [AWS and MacOS](https://github.com/splunk/attack_range/wiki/AWS:-MacOS-Installation)

1. `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/splunk/attack_range/develop/scripts/macos_deploy_aws.sh)" && cd attack_range && source venv/bin/activate`
2. `aws configure`
3. `python attack_range.py configure`


### [Azure and MacOS](https://github.com/splunk/attack_range/wiki/Azure:-MacOS-Installation)
1. `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/splunk/attack_range/develop/scripts/macos_deploy_azure.sh)" && cd attack_range && source venv/bin/activate`
2. `az login`
3. `python attack_range.py configure`


## Architecture 🏯
![Logical Diagram](docs/attack_range_architecture.png)

The virtualized deployment of Attack Range consists of:

- Windows Domain Controller
- Windows Server
- Windows Workstation
- A Kali Machine
- Splunk Server
- Phantom Server
- Zeek Sensor

Which can be added/removed/configured using [attack_range.conf](https://github.com/splunk/attack_range/blob/develop/attack_range.conf.template). More machines such as Phantom, Linux server, Linux client, MacOS clients are currently under development.

An approximate **cost estimate** for running attack_range on AWS can be found [here](https://github.com/splunk/attack_range/wiki/Cost-Estimates).

#### Logging
The following log sources are collected from the machines:

- Windows Event Logs (```index = win```)
- Sysmon Logs (```index = win```)
- Powershell Logs (```index = win```)
- Network Logs with Splunk Stream (```index = main```)
- Attack Simulation Logs from Atomic Red Team and Caldera (```index = attack```)

## Running 🏃‍♀️
Attack Range supports different actions:

- Configuring Attack Range
- Build Attack Range
- Perform Attack Simulation
- Test with Attack Range
- Destroy Attack Range
- Stop Attack Range
- Resume Attack Range
- Dump Log Data from Attack Range

### Configure Attack Range
```
python attack_range.py configure
```

### Build Attack Range
```
python attack_range.py build
```

### Show Attack Range Infrastructure
```
python attack_range.py show
```

### Perform Attack Simulation
```
python attack_range.py simulate -st T1003.001 -t ar-win-dc-default-username-33048
```

### Test with Attack Range
```
python attack_range.py test -tf tests/T1003_001.yml, tests/T1003_002.yml
```

### Destroy Attack Range
```
python attack_range.py destroy
```

### Stop Attack Range
```
python attack_range.py stop
```

### Resume Attack Range
```
python attack_range.py resume
```

### Dump Log Data from Attack Range
```
python attack_range.py dump -dn data_dump
```


### Replay Dumps into Attack Range Splunk Server
- Replay previously saved dumps from Attack Range

```
python attack_range.py replay -dn data_dump [--dump NAME_OF_DUMP]
```

- default will dump all enabled dumps described in `attack_data/dumps.yml`
- with optional argument `--dump` you can specify which dump to replay

```
python attack_range.py replay -dn data_dump --dump windows_sec_events
```

## Features 💍
- [Splunk Server](https://github.com/splunk/attack_range/wiki/Splunk-Server)
  * Indexing of Microsoft Event Logs, PowerShell Logs, Sysmon Logs, DNS Logs, ...
  * Preconfigured with multiple TAs for field extractions
  * Out of the box Splunk detections with Enterprise Security Content Update ([ESCU](https://splunkbase.splunk.com/app/3449/)) App
  * Preinstalled Machine Learning Toolkit ([MLTK](https://splunkbase.splunk.com/app/2890/))
  * pre-indexed BOTS datasets
  * Splunk UI available through port 8000 with user admin
  * ssh connection over configured ssh key

- [Splunk Enterprise Security](https://splunkbase.splunk.com/app/263/)
  * [Splunk Enterprise Security](https://splunkbase.splunk.com/app/263/) is a premium security solution requiring a paid license.
  * Enable or disable [Splunk Enterprise Security](https://splunkbase.splunk.com/app/263/) in [attack_range.conf](https://github.com/splunk/attack_range/blob/develop/attack_range.conf.template)
  * Purchase a license, download it and store it in the apps folder to use it.

- [Splunk Phantom](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html)
  * [Splunk Phantom](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html) is a Security Orchestration and Automation platform
  * For a free development license (100 actions per day) register [here](https://my.phantom.us/login/?next=/)
  * Enable or disable [Splunk Phantom](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html) in [attack_range.conf](https://github.com/splunk/attack_range/blob/develop/attack_range.conf.template)

- [Windows Domain Controller & Window Server & Windows 10 Client](https://github.com/splunk/attack_range/wiki/Windows-Infrastructure)
  * Can be enabled, disabled and configured over [attack_range.conf](https://github.com/splunk/attack_range/blob/develop/attack_range.conf.template)
  * Collecting of Microsoft Event Logs, PowerShell Logs, Sysmon Logs, DNS Logs, ...
  * Sysmon log collection with customizable Sysmon configuration
  * RDP connection over port 3389 with user Administrator

- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
  * Attack Simulation with [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
  * Will be automatically installed on target during first execution of simulate
  * Atomic Red Team already uses the new Mitre sub-techniques

- [Caldera](https://github.com/mitre/caldera)
  * Adversary Emulation with [Caldera](https://github.com/mitre/caldera)
  * Installed on the Splunk Server and available over port 8888 with user admin
  * Preinstalled Caldera agents on windows machines

- [Kali Linux](https://www.kali.org/)
  * Preconfigured Kali Linux machine for penetration testing
  * ssh connection over configured ssh key


## Support 📞
Please use the [GitHub issue tracker](https://github.com/splunk/attack_range/issues) to submit bugs or request features.

If you have questions or need support, you can:

* Join the [#security-research](https://splunk-usergroups.slack.com/archives/C1S5BEF38) room in the [Splunk Slack channel](http://splunk-usergroups.slack.com)
* Post a question to [Splunk Answers](http://answers.splunk.com)
* If you are a Splunk Enterprise customer with a valid support entitlement contract and have a Splunk-related question, you can also open a support case on the https://www.splunk.com/ support portal

## Contributing 🥰
We welcome feedback and contributions from the community! Please see our [contribution guidelines](docs/CONTRIBUTING.md) for more information on how to get involved.

## Author
* [Jose Hernandez](https://twitter.com/d1vious)
* [Patrick Bareiß](https://twitter.com/bareiss_patrick)

## Contributors
* [Bhavin Patel](https://twitter.com/hackpsy)
* [Rod Soto](https://twitter.com/rodsoto)
* Russ Nolen
* Phil Royer
* [Joseph Zadeh](https://twitter.com/JosephZadeh)
* Rico Valdez
* [Dimitris Lambrou](https://twitter.com/etz69)
* [Dave Herrald](https://twitter.com/daveherrald)
* Ignacio Bermudez Corrales
* Peter Gael
* Josef Kuepker
* Shannon Davis
* [Mauricio Velazco](https://twitter.com/mvelazco)
* [Teoderick Contreras](https://twitter.com/tccontre18)
