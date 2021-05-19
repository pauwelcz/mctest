## MCTEST

This is example of my school project in Python for monitoring IPTV channels.
Project works with argument, where you must type IP address of stream.

File is implemented mainly as sniffer/parser of MPEG-TS packet in a way that shows and updates values in about 1 seconds. To close file, you must press any key (I am not sure now, because is a long time I created it, but you can look at it as example of my backend and mainly parsing experiences :) ). 

Project monitors multicast various values as:

- type of multimedia (video, audio, etc)
- bandwidth
- out of sync in percent
- avg jitter
- peak jitter
