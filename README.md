peakflow-pcap
=============
Ever had a mitigation not block an attack and after the attack is over you have
no idea on how to tune your setup since you don't have any forensic data from
the attack? Peakflow-PCAP to the rescue!

This little app (I just love that word, sounds like it's supposed to run on a
phone) will try to automatically capture and download pcap files for running
mitigations and safely store these for you so that you may review attacks after
their completion.

Unfortunately the Arbor Peakflow API isn't the best around, so this requires
quite a bit of mechanize fiddling but that's life.

NOTE: At some point, this should probably turn into more of a service which
would poll Peakflow for running mitigations, download pcaps continuously and
then provide these over another API. Right now it doesn't do that so it might
not actually provide any real-life value.. don't complain, commit!


Fun stuff
---------
The reasponse sent by Peakflow for a PCAP download requests contains the
following headers;

Pragma:PHP-Thinks-Its-So-Smart
Cache-Control:But-It's-REALLY-DUMB


