
#This script parse additional information Windows Event 4624 from AXIOM csv export file. 
__author__ = "Matthew Pickering"
__version__ = "0.1.0"
__license__ = ""

import csv
import textwrap
import xml.etree.ElementTree as ET
import argparse 

#This function creates the output csv file and writes the column header. 
def outputFile(args):
    global of
    global CSV_Writer
    of = open(args.outputfile, 'w', newline='') 
    CSV_Writer = csv.writer(of, delimiter=',')
    RowHeader = ["CreatedTime","EventID", "EventName", "ComputerName","LogonType","SubjectUserSid","SubjectUserName","SubjectDomainName","TargetUserSid","TargetUserName","TargetDomainName", "TargetServerName", "Status","SubStatus","LogonProcessName","AuthenticationPackageName","WorkstationName","LmPackageName","ProcessName","IpAddress","IpPort"]
    CSV_Writer.writerow(RowHeader)


# This funcition parse throught the event data (the raw event data) column of the AXIOM CSV export and parsed the addtional information.
def eventParser(args, CSV_Writer, columnNum):
    global f25
    global f24
    global f48
    f25 =0
    f24 =0
    f48 =0
    with open(args.infile, mode='r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',', quotechar='"')
        columnNum = columnNum - 1       
        for row in csv_reader:
            xmlString = row[columnNum]
            if xmlString != 'Event Data':  
                try:
                    root = ET.fromstring(xmlString)    
                    EventID = root[0][1].text.rstrip()
                    CreatedDate = root[0][7].attrib['SystemTime'].rstrip()
                    Computer = root[0][12].text.rstrip()
                except:
                    print("No XML data found.")
                    break

                if EventID == '4624':
                    try:
                        Status = "-"
                        SubStatus = "-"
                        EventName = "Successful Logon"
                        TServerName = "-"
                        SUserSID = root[1][0].text.rstrip()
                        SUser = root[1][1].text.rstrip()
                        SDomain = root[1][2].text.rstrip()
                        TUserSID = root[1][4].text.rstrip()
                        TUser = root[1][5].text.rstrip()
                        TDomain = root[1][6].text.rstrip()
                        Type = root[1][8].text.rstrip()
                        LogonProcess = root[1][9].text.rstrip()
                        AuthName = root[1][10].text.rstrip()
                        Workstation = root[1][11].text.rstrip()
                        LMPackage = root[1][14].text.rstrip()
                        ProcessName = root[1][17].text.rstrip()
                        IPAddress = root[1][18].text.rstrip()
                        Port = root[1][19].text.rstrip()
                        Rowdata = [CreatedDate, EventID, EventName, Computer, Type, SUserSID, SUser, SDomain, TUserSID, TUser, TDomain, TServerName, Status, SubStatus, LogonProcess, AuthName, Workstation, LMPackage, ProcessName, IPAddress, Port]
                        CSV_Writer.writerow(Rowdata)
                    except:                 
                        f24 += 1
        
                elif EventID == '4625':
                    try:
                        EventName = "Failed Logon"
                        TServerName = "-"
                        SUserSID = root[1][0].text.rstrip()
                        SUser = root[1][1].text.rstrip()
                        SDomain = root[1][2].text.rstrip()
                        TUserSID = root[1][4].text.rstrip()
                        TUser = root[1][5].text.rstrip()
                        try:
                            TDomain = root[1][6].text.rstrip()
                        except:
                            TDomain = "-"
                        Status = root[1][7].text.rstrip()
                        SubStatus = root[1][9].text.rstrip()
                        Type = root[1][10].text.rstrip()
                        LogonProcess = root[1][11].text.rstrip()
                        AuthName = root[1][12].text.rstrip()
                        Workstation = root[1][13].text.rstrip()                
                        LMPackage = root[1][15].text.rstrip()
                        ProcessName = root[1][18].text.rstrip()
                        IPAddress = root[1][19].text.rstrip()
                        Port = root[1][20].text.rstrip()
                 
                        statusdict = {
                            '0xC000006D': 'The cause is either a bad username or authentication information.',
                            '0xC000005E': 'There are currently no logon servers available to service the logon request.',
                            '0xC0000064': 'User name does not exist',
                            '0xC000006A': 'User name is correct but the password is wrong',
                            '0xC000006E': 'Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication (such as time-of-day restrictions).',
                            '0xC000006F': 'User logon outside authorized hours',
                            '0xC0000070': 'User logon from unauthorized workstation',
                            '0xC0000071': 'User logon with expired password',
                            '0xC0000072': 'User logon to account disabled by administrator',
                            '0xC00000DC': 'Indicates the Sam Server was in the wrong state to perform the desired operation.',
                            '0xC0000133': 'Clocks between DC and other computer too far out of sync',
                            '0xC000015B': 'The user has not been granted the requested logon type (also called the logon right) at this machine',
                            '0xC000018C': 'The logon request failed because the trust relationship between the primary domain and the trusted domain failed.',
                            '0xC0000192': 'An attempt was made to logon, but the Netlogon service was not started.',
                            '0xC0000193': 'User logon with expired account',
                            '0xC0000224': 'User is required to change password at next logon',
                            '0xC0000225': 'Evidently a bug in Windows and not a risk',
                            '0xC0000234': 'User logon with account locked',
                            '0xC00002EE': 'Failure Reason: An Error occurred during Logon',
                            '0xC0000413': 'Logon Failure: The machine you are logging on to is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine.',
                            '0x0': 'Status OK.'
                       }
                    
                        if Status in statusdict:
                            Status = statusdict.get(Status)
                           
                        if SubStatus in statusdict:
                            SubStatus = statusdict.get(SubStatus)

                        Rowdata = [CreatedDate, EventID, EventName, Computer, Type, SUserSID, SUser, SDomain, TUserSID, TUser, TDomain, TServerName, Status, SubStatus, LogonProcess, AuthName, Workstation, LMPackage, ProcessName, IPAddress, Port]
                        CSV_Writer.writerow(Rowdata)                  
                    except:
                        f25+= 1

                elif EventID == "4648":
                    try:
                        EventName = "Logon attempts with Explicit Credentials"
                        Status = "-"
                        SubStatus = "-"
                        Type = "-"
                        LogonProcess = "-"
                        AuthName = "-"
                        Workstation = "-"               
                        LMPackage = "-"
                        TUserSID = "-"
                        SUserSID = root[1][0].text.rstrip()
                        SUser = root[1][1].text.rstrip()
                        SDomain = root[1][2].text.rstrip()
                        TUser = root[1][5].text.rstrip()
                        TDomain = root[1][6].text.rstrip()
                        TServerName = root[1][8].text.rstrip()
                        ProcessName = root[1][11].text.rstrip()
                        IPAddress = root[1][12].text.rstrip()
                        Port = root[1][13].text.rstrip()
                        Rowdata = [CreatedDate, EventID, EventName, Computer, Type, SUserSID, SUser, SDomain, TUserSID, TUser, TDomain, TServerName, Status, SubStatus, LogonProcess, AuthName, Workstation, LMPackage, ProcessName, IPAddress, Port]
                        CSV_Writer.writerow(Rowdata)
                    except:
                        f48 += 1
                        
# The Main Funcition 
def main():
    parser =  argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=textwrap.dedent('''\

       This script parses Logon Events (4624, 4625, 4648, ) from AXIOM's Event Data field. 

       Please provide a CSV input file generated from AXIOM and the name of a desired output file.

       The scirpt will ask you what the column number is for the Event Data field/column in your AXIOM file.     
    '''))
    
    #Add Required Arguments 
    parser.add_argument( "infile", action = 'store', type = str)
    parser.add_argument( "outputfile", action = 'store', type = str)
      
    args = parser.parse_args()
    

    global columnNum
    columnNum = input("What is the column number of the Event Data field? ")
    columnNum = int(columnNum)

       
    outputFile(args)
    eventParser(args, CSV_Writer, columnNum)
    
    of.close()
    print( f24,"- 4624 Events did not contain the expected values and were skipped.")
    print( f25,"- 4625 Events did not contain the expected values and were skipped.")
    print( f48,"- 4648 Events did not contain the expected values and were skipped.")


# Main Script Call
if __name__ == "__main__":
    main()       

    