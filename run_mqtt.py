#!/usr/bin/env python
import subprocess as s
import time
import sys
import random
import string

# broker
s.call(["sudo","echo",'\x1b[6;30;42m' + 'Starting Mosquitto Broker' + '\x1b[0m'])
try:
    # generating passwords
    lispass =  ''.join([random.choice(string.ascii_lowercase +string.ascii_uppercase + string.digits) for _ in range(32)])
    senpass =  ''.join([random.choice(string.ascii_lowercase +string.ascii_uppercase + string.digits) for _ in range(32)])
    # updating passwords        
    s.call(['touch','mqpass'])
    s.call(["mosquitto_passwd","-b", "mqpass", "beamer",lispass])
    s.call(["mosquitto_passwd","-b", "mqpass", "remote-control",senpass])
    time.sleep(1)
    # reloading mosquitto config
    p = s.Popen(["mosquitto", "-v", "-c", "mosquitto.conf"])
    time.sleep(1)
    p.send_signal(1)
    time.sleep(1)

    # subscriber
    s.call(["sudo","echo",'\x1b[6;30;42m' + 'Starting Beamer Device as Subcriber' + '\x1b[0m'])
    listener = s.Popen(["mosquitto_sub","-h","localhost","-t","/uos/93/E06/beamer-control","-u","beamer","-P",lispass],stdout=s.PIPE,stderr=s.PIPE)
    time.sleep(1)
except Exception,e:
    print >> sys.stderr, '\x1b[1;37;41m' + 'An error occured, maybe mosquitto/_sub/_passwd is not installed' + '\x1b[0m'
    raise e
    exit()

# sniffer
s.call(["sudo","echo",'\x1b[6;30;42m' + 'Starting Sniffer' + '\x1b[0m'])
try:
    ## Nach langem erfragen wie man valgrind aufrufen soll
    sniff = s.Popen(['sudo','valgrind','--suppressions=alpine.supp','--leak-check=full','--show-leak-kinds=all','./sniffer'])
    time.sleep(1)
    if sniff.poll():
        raise Exception("Sniffer terminated or never started")
except:
    print >> sys.stderr, '\x1b[1;37;41m' + '404 Programm sniffer not found' + '\x1b[0m'
    raw_input("Press key after manually starting the sniffer")
    sniff = None


# second subscriber (random)
fake = random.randint(0, 1)
if (fake):
    try:
        s.call(["sudo","echo",'\x1b[6;30;42m' + 'Starting Beamer Device as Subcriber again' + '\x1b[0m'])
        fakelistener = s.Popen(["mosquitto_sub","-h","localhost","-t","/uos/93/E06/beamer-control","-u","beamer","-P","fake"],stdout=s.PIPE,stderr=s.PIPE)
        time.sleep(1)
    except Exception,e:
        print >> sys.stderr, '\x1b[1;37;41m' + 'An error occured, mosquitto_sub could not be connected.' + '\x1b[0m'
        raise e
        exit()

# publisher
s.call(["sudo","echo",'\x1b[6;30;42m' + 'Starting Beamer Remote Control as Publisher' + '\x1b[0m'])
s.call(["mosquitto_pub","-h","localhost","-t","/uos/93/E06/beamer-control","-m","beamer_on","-u","remote-control","-P",senpass])
if sniff:
    try:
        sniff.wait()
    except:
        pass
time.sleep(2)
listener.kill()
if (fake):
    fakelistener.kill()
p.kill()

# report
print "\n================================="
print ('\x1b[6;30;42m' + 'Received Messages:' + '\x1b[0m')

for line in listener.stdout:
    print line[:-1]
print "================================="

