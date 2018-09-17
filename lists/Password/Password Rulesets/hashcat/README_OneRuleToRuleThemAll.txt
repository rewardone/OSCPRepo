See comparison results from other rulesets here: https://www.notsosecure.com/one-rule-to-rule-them-all/
Download a fresh copy here: https://github.com/NotSoSecure/password_cracking_rules

Hashcat was invoked like so:
hashcat64.exe -m0 B:\Leaks\lifeboat-raw B:\Dictionaries\rockyou.txt --status -w34 --debug-mode=1 --debug-file=stats-lifeboat-best64 -o lifeboat-best64 --potfile-disable -r rules\best64.rule

You should be able to invoke hashcat with the -r to specify the OneRuleToRuleThemAll.rule
