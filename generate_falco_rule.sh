#!/bin/bash

set -e  

if [ $# -ne 1 ]; then
  echo "Usage: $0 <baseline_json_path>"
  exit 1
fi

INPUT_JSON="$1"
if [ ! -f "$INPUT_JSON" ]; then
  echo "Error: $INPUT_JSON not found!"
  exit 1
fi

# Derive base name (without extension) for rule file
FILENAME=$(basename "$INPUT_JSON" .json)
PODNAME=${FILENAME#execution_profile_}
RULE_FILE="${PODNAME}.falco.yaml"

# Initialize Falco rule file and add macros
cat <<EOF > "$RULE_FILE"
- required_engine_version: 10

- macro: ignore_containerd_shim
  condition: proc.exepath != "/usr/bin/containerd-shim-runc-v2"

- macro: valid_exe_inode
  condition: proc.exe_ino exists
EOF

# Process each pod
for POD_NAME in $(jq -r 'keys[]' "$INPUT_JSON"); do
  echo "[*] Generating rule for pod: $POD_NAME"

  # Filter and extract only non-null values
  EXE_LIST=$(jq -r --arg pod "$POD_NAME" '.[$pod][] | select(.exe != null) | .exe' "$INPUT_JSON" | sort -u | jq -R -s -c 'split("\n")[:-1]')
  EXEPATH_LIST=$(jq -r --arg pod "$POD_NAME" '.[$pod][] | select(.exepath != null) | .exepath' "$INPUT_JSON" | sort -u | jq -R -s -c 'split("\n")[:-1]')
  PROCNAME_LIST=$(jq -r --arg pod "$POD_NAME" '.[$pod][] | select(.procname != null) | .procname' "$INPUT_JSON" | sort -u | jq -R -s -c 'split("\n")[:-1]')
  CWD_LIST=$(jq -r --arg pod "$POD_NAME" '.[$pod][] | select(.cwd != null) | .cwd' "$INPUT_JSON" | sort -u | jq -R -s -c 'split("\n")[:-1]')
  EXEINO_LIST=$(jq -r --arg pod "$POD_NAME" '.[$pod][] | select(.exe_inode != null) | .exe_inode' "$INPUT_JSON" | sort -u | jq -R -s -c 'split("\n")[:-1]')

  # Escape for Falco syntax
  EXE_VALUES=$(echo "$EXE_LIST" | jq -r '.[] | @sh' | paste -sd "," -)
  EXEPATH_VALUES=$(echo "$EXEPATH_LIST" | jq -r '.[] | @sh' | paste -sd "," -)
  PROCNAME_VALUES=$(echo "$PROCNAME_LIST" | jq -r '.[] | @sh' | paste -sd "," -)
  CWD_VALUES=$(echo "$CWD_LIST" | jq -r '.[] | @sh' | paste -sd "," -)
  EXEINO_VALUES=$(echo "$EXEINO_LIST" | jq -r '.[]' | paste -sd "," -)

  # Build Falco condition dynamically
  CONDITION="k8s.pod.name=\"$POD_NAME\" and evt.type in (execve,execveat,clone,fork,vfork) and ignore_containerd_shim and valid_exe_inode"
  CLAUSES=()

  [ -n "$EXE_VALUES" ] && CLAUSES+=("not (proc.exe in ($EXE_VALUES))")
  [ -n "$EXEPATH_VALUES" ] && CLAUSES+=("not (proc.exepath in ($EXEPATH_VALUES))")
  [ -n "$CWD_VALUES" ] && CLAUSES+=("not (proc.cwd in ($CWD_VALUES))")
  [ -n "$EXEINO_VALUES" ] && CLAUSES+=("not (proc.exe_ino in ($EXEINO_VALUES))")

  if [ ${#CLAUSES[@]} -gt 0 ]; then
    CONDITION="$CONDITION and ("
    for ((i = 0; i < ${#CLAUSES[@]}; i++)); do
      [ $i -gt 0 ] && CONDITION="$CONDITION or "
      CONDITION="$CONDITION${CLAUSES[$i]}"
    done
    CONDITION="$CONDITION)"
  fi

  # Append rule block to Falco file
  cat <<EOF >> "$RULE_FILE"

- rule: Execution Anomaly in Pod $POD_NAME
  desc: Detect anomalous execution behavior in pod $POD_NAME
  condition: >
    $CONDITION
  output: Anomalous execution in pod $POD_NAME (podname=%k8s.pod.name exe=%proc.exe exepath=%proc.exepath exe_ino=%proc.exe_ino cwd=%proc.cwd)
  priority: CRITICAL
  tags: [pod, execution, anomaly, detection]
EOF

done

echo "Falco rules generated successfully in $RULE_FILE"
