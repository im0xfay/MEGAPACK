import sys
cve = sys.argv[1] if len(sys.argv)>1 else "CVE-2026-90907"
name = sys.argv[2] if len(sys.argv)>2 else "Joomla! Core"
desc = sys.argv[3] if len(sys.argv)>3 else "unauth account creation via com_users profile.save"
P="\033[95m"; R="\033[0m"
line="="*60
print(f"{P}{line}")
print(f"  0xfay x Cyber Alpha Labs")
print(f"● {cve}")
print(f"● {name}")
print(f"  {desc}")
print(f"{line}{R}")
