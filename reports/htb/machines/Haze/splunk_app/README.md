
A modified copy of https://github.com/DimopoulosElias/SplunkAppShell

Update `ATTACKER_IP` in [revshell/bin/reverse_shell.py](revshell/bin/reverse_shell.py) and then run this tar command to create the gzipped Splunk App:
```
tar cvzf revshell.tgz revshell
```