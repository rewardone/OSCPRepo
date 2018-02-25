So what do I do with these?

OCLHashcat has support for these mask files. Just use the attack mode 3 (brute force) option and 
provide the list of masks to use in a text file.

./oclHashcat64.bin -m 1000 hashes.txt -o output.txt -a 3 2015-Top40-Time-Sort.hcmask

When should I use these?

Personally, I would use these after I’ve gone through some dictionaries and rules. 
Since this is a brute force attack (on a limited key-space) this is not always as 
efficient as the dictionary and rule-based attacks. However, I have found that this 
works well for passwords that are not using dictionary words. For example, a 
dictionary and rule would catch Spring15, but it would be less likely to catch 
Gralwu94. However, Gralwu94 would be caught by a mask attack in this situation.

How long would this take?

That depends. We have a couple of GPU cracking boxes that we can distribute this 
against, but if we just ran it on our main cracking system, it would take about 
three and a half days to complete. That’s a really long time. There’s a few weird 
ones in the list that were easy to crack with word lists and rules (resulting in 
lots of mask hits), but they take a long time to brute force the key space 
(?u?l?l?l?l?l?l?l?l?l?d?d – Springtime15). I went through and time stamped each of 
the top 40 and created a time sorted list that you can quit using when you start 
hitting your own time limits.