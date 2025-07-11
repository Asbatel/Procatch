# Procatch

![Platform](https://img.shields.io/badge/platform-Kubernetes-blue)
![Language](https://img.shields.io/badge/script-Bash-green)

This repository contains the code for the paper:

> **Procatch: Detecting Execution-based Anomalies in Single-Instance Microservices**  
> Asbat El Khairi, Andreas Peter, Andrea Continella  
> University of Twente, University of Oldenburg  
> *To appear at [IEEE Conference on Communications and Network Security], 2025*

---

## Overview

**Procatch** is a novel approach to container anomaly detection that requires no training. It builds on the inherently bounded nature of microservices—each designed to perform a narrow, single task—to quickly and reliably detect unexpected behavior.


## Requirements

- `Falco` must be installed and running
- `kubectl` and `crictl` must be available on the system

> **Note:**  
> This script is designed for a **single-node Kubeadm setup** using the `containerd` runtime.  
> In other environments—such as **managed clusters** or setups where the **control plane is not accessible from worker nodes**—the script must be executed **on the worker node** where the target pod is running. You might retrieve pod information externally using the **Kubernetes API server**, or modify the script to **accept the container name or ID as input**, which you can obtain using commands such as `crictl ps`.


## Usage

### 1. Baseline

```bash
./baseline.sh <namespace> <pod-name> 
```
### 2. Falco Rules

```bash
./generate_falco_rule.sh <pod_baseline.json> 
```

### 3. Monitor

```bash
falco -r <pod_falco_rule.yaml> 
```
