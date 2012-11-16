hppm
====

Simple high perfomance port mapper

Installation
------------
$ sudo apt-get install libevent-dev libpcre++-dev

$ g++ hppm.cpp -levent -lpcre -o hppm

Usage
------------
Syntax:
   hppm [-l filename] [-r regexp] <listen-on-addr> <connect-to-addr>
   
     -l - enables logging of all transit packets to file <filename>
     
     -r - enables filtering of all data satisfied a POSIX regular expression <regexp>
          all filtered data then will translated to stdout
Example:

   hppm 127.0.0.1:8888 1.2.3.4:80
   
   hppm -l log.txt -r [0-9a-f]{32} 127.0.0.1:1234 95.34.12.33:80

