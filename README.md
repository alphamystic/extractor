# extractor
Extractor is a simple golang engine to extract files from a pcap.

This script should not be used for a production setup as it might slow things down. Try with EBPF or something else at roouter level(Like firewalls do)



The whole point is to be able to run a binary or click a link,open a pdf/word document then follow a TA from initial access to ransomware or exfill from a pcap before going ahead to RE given binaries. An endgoal to have this for IR n generating artifacts.


We will borrow from this https://github.com/lktp/extractor/blob/master/pcap_extractor.py


Cases, make them like a small article
have tags of threatfamily,Adminsapprooved,falsepositive
