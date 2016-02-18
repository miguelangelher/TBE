#!/usr/bin/python

__author__ = 'Miguel Angel Hernandez Ruiz'

import sys
import os
import time
import argparse
from requests import Request, Session
from threading import *

# Prints the use of the tool
def usage():
    print "Time Based Enumeration Tool"
    print
    print "This script aims to be a tool for guessing when a user belongs to certain domain based in the server response time"
    print "This tool is capable of identifying if the parameter is placed in the URL or in the body and fuzz the proper field"
    print
    print "NOTE: as much threads were run, most error probability you will have. Take into acount that the number of requests"
    print "to the server has a direct infuence in the request reponse time and therefore in the guessing process. Not more"
    print "than 5 threads are recommended."
    print
    print "NOTE2: in orther this script to be useful the response time difference between an existent user identification re-"
    print "quest and a non-existent one should be long. the longer the time difference, the better the user estimation pro- "
    print "cess will be."
    print
    print "Usage: ./tbe.py -f file -r runfield -d dictionary -t thresholdtime [-n threads][-e exectime]"
    print "-f --file                    - read the Request from the file [file] in ZAP format. Before save it in raw (headers + body)"
    print "-r --runfield                - fieldname of the username in the request which will be fuzzed"
    print "-d --dictionary              - uses de dictionary [dictionary] to fuzz the field [runfield]"
    print "-t --thresholdtime           - Threshold which if exceeded, the username is considered as a match (in miliseconds)"
    print "[-n] [--nthreads]            - [OPTIONAL] number of paralel threads to run, 3 by default"
    print
    print
    print "Examples: "
    print "Load the request in the request.req file, fuzz the username field using the nifs.dic dictionary and"
    print "when the login time exeeds 1 second, consider that the username exists"
    print "tbe.py -f request.raw -r username -d nifs.dic -t 1000"
    print "Similar to the previous one but using the optional parameters to set 200 threads"
    print "tbe.py -f request.raw -r username -d nifs.dic -t 1000 -n 3"
    sys.exit(0)


# Basic parameter checking function. It checks if the essential parameters have been typed, if the files are readable #
# and actually files and if the number of threads is a numeric value.

def checkParameters(options):
    if not (options.file or options.runfield or options.dictionary or options.thresholdtime):
        print "[-] missing mandatory argument... try again! \n"
        sys.exit(0)
    if not (os.path.isfile(options.file) or os.access(options.file, os.R_OK)):
        print "[-] " + options.file + " does not exist or do not have read permission for this user. \n"
        sys.exit(0)
    if (not os.path.isfile(options.dictionary) or not os.access(options.dictionary, os.R_OK)):
        print "[-] " + options.dictionary + " does not exist or do not have read permission for this user. \n"
        sys.exit(0)
    if options.nthreads:
        try:
            int(options.nthreads)
        except:
            print "[-] the number of threads must be numeric"
            sys.exit(0)
    return True


# create the parser and add the arguments
def parseInput():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('-f', '--file', dest='file')
        parser.add_argument('-r', '--runfield', dest='runfield')
        parser.add_argument('-d', '--dictionary', dest='dictionary')
        parser.add_argument('-t', '--thresholdtime', dest='thresholdtime')
        parser.add_argument('-n', '--nthreads', dest='nthreads', default=3)
        args = parser.parse_args()
        checkParameters(args)
        return args
    except:
        print "[-] parseInput exception"
        exit(0)

# This method returns a request object read from a file previouly exported as raw format from ZAP Proxy. This request #
# is then used to fuzz the parameter and send it to the server awaiting for a response and measuring the reseponse ti-#
# me.
def createRequestFromFile(fileName):
    try:
        lines = [line.strip() for line in open(fileName)]
        method = lines[0].split(' ')[0]
        url = lines[0].split(' ')[1]
        headers = {}
        content = {}
        inHeaders = True
        for line in lines[1:]:
            if not line:
                inHeaders = False
                continue
            if inHeaders:
                (key, value) = line.split(': ')
                headers.update({key: value})
            else:
                parameters = line.split('&')
                for parameter in parameters:
                    (paramName, paramValue) = parameter.split('=')
                    content.update({paramName: paramValue})
        request = Request(method, url, data=content, headers=headers)
        return request
    except:
        print '[-] Exception creating request from file'
        exit(0)

# This is the fuction to send the fuzzed request to the server. Each new thread will send the information provided by #
# the parent thread. As commented below, there is an important matter to be aware involving the shared memory. Check  #
# the comments for the method below.

screenLock = Semaphore(value=1)
def sendRequest(session, prepRequest, freeSlot, threshold, word):
    try:
        start = int(round(time.time() * 1000))
        resp = session.send(prepRequest)#,proxies={"http":"127.0.0.1:8085"}) --> set here a proxy for debuggin purposes and uncoment this line
        stop = int(round(time.time() * 1000))
        elapsed = stop - start
        if elapsed >= int(threshold):
            screenLock.acquire()
            print "\033[1;31m[+] User found!: \033[1;m" + word
        else:
            screenLock.acquire()
            print "[-] The user " + word + " seems not to be in the system"
    except:
        print '[-] Request ended with errors'
    finally:
        screenLock.release()
        freeSlot.set()

# This method is the core of the script. It is focused in substituting the fuzzed parameter for those present in the #
# dictionary. Despite it seems to be easy, in a multithreading approach the threads are sharing the memory with the  #
# parent and this fact causes a great number of problems. When the parent thread allocates memory, it is shared by   #
# created threads through the parameters. It implies that when the parent changes the value, the child threads change#
# it as well and the fuzzed parameter is not correctly sent to the server. I think this is because the parameter subs#
# titution is being done before the prepare_request call and not after it. It is still pending of verifying this fact#
# in a new version

def fuzz(request, fuzzfield, dictionary, threshold, nthreads):

    fuzzinurl = False
    fuzzinbody = False
    intNthreads = int(nthreads)

    try:
        if request.url.find(fuzzfield) != -1:
            fuzzinurl = True
            print "[+] Parameter found in the URL!"
        else:
            for parameter in request.data:
                if parameter == fuzzfield:
                    fuzzinbody = True
                    print "[+] Parameter found in the BODY!"
                    break
        if not (fuzzinurl or fuzzinbody):
            print '[-] The parameter does not match any of the ones present in the URL or the Request body'
            exit(0)

        if fuzzinurl:
            #codigo pendiente de depuracion
            splitparameters = request.url.split(fuzzfield + "=")
            if splitparameters[1].find('&') != -1:
                isolatedvalues = splitparameters[1].split('&')
                replacedvalue = isolatedvalues[0]
            else:
                replacedvalue = splitparameters[1]
            print "replacedvalue: " + replacedvalue


        threadPool = []
        freeSlot = Event()  # necessary to coordinate the Threads
        dictfile = open(dictionary)
        dictfileeof = False
        oldURL = request.url #necessary to make the substututions for the fuzz in the URL
        s = Session()
        for nThread in range(0, intNthreads):
            word = dictfile.readline()
            word = word.strip('\n')
            if word == '': #EOF reached because there are less words in the dictionary than paralel threads specified
                print "[i] EOF reached because there are less words in the dictionary than paralel threads specified"
                dictfile.close()
                dictfileeof = True
                break
            if fuzzinurl:
                replacedUrl = oldURL.replace(replacedvalue, word)
                newRequest = Request(method=request.method,url=replacedUrl,headers=request.headers,data=request.data)
                request = newRequest
            elif fuzzinbody:
                request.data[fuzzfield] = word

            # the next two lines are key: if the request is not prepared before satarting the thread  #
            # the reference to the object is passed as a value and the main process continuously modi-#
            # fies the word with the new read from the dictionary file. Thus, all threads would execu-#
            # te the sending with the last word read from the main process                            #
            prepRequest = s.prepare_request(request)
            threadPool.append(Thread(target=sendRequest, args=[s,prepRequest, freeSlot, threshold, word]))
            threadPool[nThread].start()

        if not dictfileeof:
            for word in dictfile:
                word = word.strip('\n')
                if fuzzinurl:
                    replacedUrl = oldURL.replace(replacedvalue, word)
                    newRequest = Request(method=request.method,url=replacedUrl,headers=request.headers,data=request.data)
                    request = newRequest
                elif fuzzinbody:
                    request.data[fuzzfield] = word
                prepRequest = s.prepare_request(request)
                freeSlot.wait()
                new_thread = Thread(target=sendRequest, args=[s,prepRequest, freeSlot, threshold, word])
                threadPool.append(new_thread)
                new_thread.start()
            dictfile.close()
    except:
        print '[-] Exception in fuzzing method'

#This script aims to be a tool for guessing when a user belongs to certain domain based in the server response time#

#NOTE: as much threads were run, most error probability you will have. Take into acount that the number of requests#
#to the server has a direct infuence in the request reponse time and therefore in the guessing process. Not more   #
#than 5 threads are recommended.

#NOTE2: in orther this script to be useful the response time difference between an existent user identification re-#
#quest and a non-existent one should be long. the longuer the time difference, the better the user estimation pro- #
#cess will be.

def main():
    try:
        arguments = parseInput()
    except:
        usage()

    print "[+] Creating request...."
    request = createRequestFromFile(arguments.file)
    print "[+] Ready to fuzz...."
    fuzz(request,arguments.runfield,arguments.dictionary,arguments.thresholdtime,arguments.nthreads)


main()
