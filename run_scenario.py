import sys, json, time, subprocess, os
from datetime import datetime, timezone

# كل سيناريو: اسم، تسمية، أوامر
SCENARIOS = {
    "normal_packages": ("noise", [
        "sudo apt install -y figlet", "sudo apt remove -y figlet"]),
    "normal_admin": ("noise", [
        "sudo ls /root", "sudo whoami", "sudo systemctl status ssh --no-pager"]),
    "attack_ssh_bruteforce": ("threat", [
        "for i in 1 2 3 4 5 6; do ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=3 attacker$i@localhost exit; done"]),
    "attack_persistence": ("threat", [
        "sudo useradd -m evil_svc", "sudo usermod -aG sudo evil_svc",
        "sudo userdel -r evil_svc"]),
    "attack_sensitive_file": ("threat", [
        "sudo bash -c 'echo \"# t\" >> /etc/hosts'",
        "sudo sed -i '/^# t$/d' /etc/hosts"]),
}

name = sys.argv[1]
label, cmds = SCENARIOS[name]
start = datetime.now(timezone.utc)
for c in cmds:
    print("$", c)
    subprocess.run(c, shell=True)
    time.sleep(2)
time.sleep(5)
end = datetime.now(timezone.utc)

data = json.load(open("scenarios.json")) if os.path.exists("scenarios.json") else []
data.append({"name": name, "label": label,
             "start": start.isoformat(), "end": end.isoformat()})
json.dump(data, open("scenarios.json", "w"), indent=2)
print("saved:", name, label)
