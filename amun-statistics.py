#!/usr/bin/python
import sys
import getopt
import GeoIP

#
# Parse Amun Honeypot submissions.log file (from standardin) and generate statistics
#
#       Version: 0.2 (WIP)
#       Date:    2010-05-06
#
# Author: Miguel Cabrerizo
# email : doncicuto@gmail.com
#
# This python script is based on Andrew White's submission2stats.py
# Andrew White's blog: blog.infosanity.co.uk
#
# Amun Honeypot can be downloaded from amunhoney.sourceforge.net - Jan Gobel
#
# GeoIP code obtained from afurlan's blog (blog.afurlan.org)
#

# Change Log:
#       Version 0.1 (2010-05-04):
#               First version of this script
#       Version 0.2 (2010-05-06)
#               Adding GeoIP support
#

#Global vars, set
verbose = False
path= "/opt/amun/logs"

#class stores logged submission entries
class Submission:
        def __init__( self, date, time, sourceIP, sourceURL, malwareMD5, vulnerability, country):
                self.date = date
                self.time = time
                self.sourceIP = sourceIP
                self.sourceURL = sourceURL
                self.malwareMD5 = malwareMD5
                self.vulnerability = vulnerability
                self.country = country

        def out(self):
                str =  self.date + ', ' + self.time + ', ' + self.sourceIP + ', ' + self.sourceURL + ', ' + self.malwareMD5 + ', ' + self.vulnerability
                return str


#/End class def

#class  generates and stores submission stats
class Stats:
        def __init__(self):
                self.submissions = 0
                self.samples = 0
                self.sourceIPs = 0
                self.vulnerabilities = 0
                self.firstDate = None
                self.lastDate = None
                self.submissionList = []

        def incNumSubmissions(self):
                self.submissions += 1

        def getNumSubmissions(self):
                return (self.submissions)

        def incNumSamples(self):
                self.samples += 1

        def getNumSamples(self):
                return (self.samples)

        def incNumSourceIPs(self):
                self.sourceIPs += 1

        def getNumSourceIPs(self):
                return (self.sourceIPs)

        def incNumVulnerabilities(self):
                self.vulnerabilities += 1

        def getNumVulnerabilities(self):
                return (self.vulnerabilities)

        #Parses Amun Honeypot submissions.log file from stdin
        def parseLogged_Submissions(self):
        
                # geoip database from "geoip-database" debian package
                GEOIP_DATABASE = '/usr/share/GeoIP/GeoIP.dat'
                geoip = GeoIP.open(GEOIP_DATABASE, GeoIP.GEOIP_STANDARD)

                #Create list of log entries from standard input
                while 1:
                        #read stdin and break loop if EoF
                        line = sys.stdin.readline()
                        if not line:
                                break

                        #Split input line to composite parts
                        logData = line.split(' ');

                        #If submit is set to submit_md5 extract data

                        if logData[3] == '[submit_md5]':
                                date = logData[0]
                                time = logData[1].split(',')[0]
                                sourceIP = logData[5].split('/')[2].split(':')[0]
                                sourceMalware = logData[5].split('/')[3].split(')')[0]
                                malwareMD5 = logData[6]
                                vulnerability = logData[10]
                                #country = geoip.country_code_by_addr(sourceIP)
                                country = geoip.country_name_by_addr(sourceIP)

                                #create new Submission object with log line contents
                                sub = Submission(date, time, sourceIP, sourceMalware, malwareMD5, vulnerability, country)
                                self.submissionList.append(sub)

                                #update statistics
                                self.incNumSubmissions()
                                
                                if self.firstDate:
                                        pass
                                else:
                                        self.firstDate = sub.date
                                self.lastDate = sub.date


        def generateStats(self):
                uniqueSamples = []
                sourceIPs = []

                #iterate through submissions and create stats
                for entry in self.submissionList:
                        #Handle log MD5 hash
                        if entry.malwareMD5 in uniqueSamples:
                                pass
                        else:
                                uniqueSamples.append(entry.malwareMD5)
                                self.incNumSamples()

                        #Handle log source IP
                        if entry.sourceIP in sourceIPs:
                                pass
                        else:
                                sourceIPs.append(entry.sourceIP)
                                self.incNumSourceIPs()


        #Returns 'entries' most recent log lines (similar to tail)
        # as list of submission objects
        def getRecent(self):
                if self.getNumSubmissions() >= 5:
                   entries = 5
                else:
                   entries = self.getNumSubmissions()
                recent = []
                for i in range( 1, ( entries + 1 ) ):
                        recent.append( self.submissionList[self.submissions - i] )

                return recent


        def out(self):

                sourceCountries = []
                sourceVulnerabilities = []

                sys.stdout.write("\nStatistics engine written by Andrew Waite (www.infosanity.co.uk) modified by Miguel Cabrerizo (diatel.wordpress.com)\n\n")
                sys.stdout.write("Number of submissions      : %i\n" %(self.getNumSubmissions()))
                sys.stdout.write("Number of unique samples   : %i\n" %(self.getNumSamples()))
                sys.stdout.write("Number of unique source IPs: %i\n" %(self.getNumSourceIPs()))
                sys.stdout.write("\n")


                sys.stdout.write("Origin of the malware:\n")
                recentSubmissions = self.getRecent()
                for sub in self.submissionList:
                        sourceCountries.append(str(sub.country))
                        sourceVulnerabilities.append(sub.vulnerability)

                setCountry = set(sourceCountries)

                for cntr in setCountry:
                        sys.stdout.write( "\t %15s : "  %cntr)
                        sys.stdout.write( "%5s" %(sourceCountries.count(cntr)))
                        sys.stdout.write("\n")

                sys.stdout.write("\nVulnerabilities exploited:\n")

                setVulnerabilities = set(sourceVulnerabilities)

                for vuln in setVulnerabilities:
                        sys.stdout.write( "\t %15s : " %vuln.rstrip())
                        sys.stdout.write( "%5s" %(sourceVulnerabilities.count(vuln)))
                        sys.stdout.write("\n")

                sys.stdout.write("\nMost recent submissions:\n")
                recentSubmissions = self.getRecent()
                for sub in recentSubmissions:
                        sys.stdout.write( "\t %s" %(sub.out()) )
                sys.stdout.write("\n")
#/End class def


#parse commandline options
def parseOpts():
        #Tutorial at http://docs.python.org/library/getopt.html used as basis
        try:
                opts, args = getopt.getopt(sys.argv[1:], "ho=vV", ["help", "output=", "Version"])
        except getopt.GetoptError, err:
                print str(err)
                usage()
                sys.exit(2)

        global output
        verbose = False
        for o, a in opts:
                if o == "-v":
                        verbose = True
                elif o in ("-h", "--help"):
                        usage()
                        sys.exit()
                elif o in ("-V", "--version"):
                        version()
                        sys.exit()
                else:
                        assert False, "unhandled option"

def usage():
        sys.stdout.write("Parses Amun Honeypot submissions.log file (read from stdin) to generate statistics\n")
        sys.stdout.write("Written by Andrew Waite modified for Amun by Miguel Cabrerizo, www.infosanity.co.uk\n")
        sys.stdout.write("\n")
        sys.stdout.write("Typical usage:\n")
        sys.stdout.write("\tcat /opt/amun/logs/submissions.log | ./amun_submissions_stats.py\n")
        sys.stdout.write("\n")
        sys.stdout.write("Options:\n")
        sys.stdout.write("\t -h, --help \t\t \n")
        sys.stdout.write("\t -V, --version \t\t Display version info\n")


def version():
        sys.stdout.write("amun_submissions_stats.py version 0.2\n")
        sys.stdout.write("--\n")
        sys.stdout.write("Miguel Cabrerizo @ http:\\\\diatel.wordpress.com  based on Andrew Waite's work @ ")
        sys.stdout.write("http:\\\\www.infosanity.co.uk\n")

def main():
        parseOpts()
        stats = Stats()
        stats.parseLogged_Submissions()
        stats.generateStats()
        stats.out()

if __name__ == "__main__":
        main()
