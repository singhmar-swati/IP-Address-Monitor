"""  
*****************************************************  Program By: Compe209 Team4  ***********************************************************************
                                                       SHIVANI SINHMAR  (011450075)
                                                       HIMANSHU MISHRA  (011414949)
                                                       NAVEEN RAVI      (011413571)
                                                       NIKITA AGARWAL   (011448450)



****************************************************NETWORK ANALYZER AND IP LOCATOR TOOL******************************************************************

"""
import os
import pygeoip
import socket
import time
import webbrowser
from scapy.all import *
import simplekml
from random import randint
from datetime import datetime
from pytz import timezone
import pytz
from ipwhois import IPWhois
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import webbrowser


#This is the list of blacklisted ip's that are not allowed to access by users.

blacklisted_ip = ['70.32.1.32','52.19.167.6']


#This the root directory for saving our report.
ROOT_DIR = 'REPORT'

xyz = []


#lat_list is used to store the latitude of the IP addresses.
lat_list=[]


#long_list is used to store the longitude of the IP addresses.
long_list=[]



"""

  The create_dir function is used for creating a new directory.It first checks if the directory already exists or not.If not then it creates a new directory.

"""

 
def create_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


"""

  The write_file function is used for writing data into a file.The path of the file and data to be stored is passed as an argument to this function.

"""


def write_file(path, data):
    with open(path, 'a') as f:
        f.write(data)

        
"""

  The parse_packet function is used for parsing the pcap file for IP addresses.The pcap file is passed as an argument to this function.It uses the scapy  
  module in python for checking each packet for the blacklisted ip's.

"""   


def parse_packet(pcap):
    pkts = rdpcap(pcap)
    for pkt in pkts:
        if IP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            if ip_dst in blacklisted_ip:
                if ip_src not in xyz:
                    xyz.append(ip_src)
                    geo_city(str(ip_src))
                else:
                    pass



"""

  The geo_city function is used for generating all geographical information from the IP addresses. It uses the GeoLiteCity data base for locating the IP
  addresses.It uses pygeoip module in python which returns a dictonary that has all the parameters of the corresponding IP address. 

"""


def geo_city(string):
    path = 'GeoLiteCity.dat'
    gic = pygeoip.GeoIP(path)
    a = gic.record_by_addr(string)
    pcity=a['city']
    pcountry=a['country_name']
    plongitude = a['longitude']
    platitude = a['latitude']
    long_list.append(plongitude)
    lat_list.append(platitude)
    print_report(pcity,pcountry,plongitude,platitude,string)


  
"""

  The print_report function is used for printing all the information about the IP addresses along with the time stamp.It uses the write_file fuction for appending 
  the information of all IP addresses in single report.

"""



def print_report(pcity,pcountry,plongitude,platitude,string):
    num = randint(1,50000000)
    date_format = '%m/%d/%Y %H:%M:%S %Z'
    date=datetime.now(tz=pytz.utc)
    date=date.astimezone(timezone('US/Pacific'))
    record='\n' + "**********************************"+'\n'+"Abuse Incident Number :" + str(num) +'\n' +"IP Address-: " + str(string)+'\n'+ "city - " + str(pcity) + " \n" + "country -" + str(pcountry) + " \n" + "longitude-" + str(plongitude) + " \n" + "latitude - " + str(platitude) +'\n'+ str( date.strftime(date_format))+'\n'
    write_file (ROOT_DIR + "/report.txt" , str(record))
    whois_lookup(string)



"""
    
   The whois_lookup function is used to extract the email address of the IP addresses.It uses whois module for accessing the whois database.

""" 


    
def whois_lookup(string):
    obj=IPWhois(string)
    results=obj.lookup_whois()
    email_id=str((results["nets"][0]['emails'])[0])
    send_email(email_id)


   
"""

  The send_email fuction is used to send the email to user for notification of improper act.It uses email and smtp module for this purpose.The body of the mail 
  is stored in a text file(message.txt)

""" 


 
def send_email(email_id):
    fromaddr = "cmpe209team14@gmail.com"
    toaddr = "himanshu.mishra@sjsu.edu"
    msg = MIMEMultipart()
    msg['From'] = fromaddr
    msg['To'] = toaddr
    msg['Subject'] = "Notice of Claim of Copyright Infringement."
 
    message=open("message.txt","r")
    body = message.read()
    msg.attach(MIMEText(body, 'plain'))
 
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(fromaddr, 'chaolitrang')
    text = msg.as_string()
    server.sendmail(fromaddr, toaddr, text)
    server.quit()



"""

  The kml_file function is used for creating a kml file for locating IP addresses on Google maps.It uses simplekml module for this purpose.

""" 

  
def kml_file():
    a=len(lat_list)
    kml = simplekml.Kml()
    for i in range (0,a):
        pnt = kml.newpoint(name = 'Point')
        pnt.coords = [(long_list[i] ,lat_list[i])]
    kml.save("google_maps.kml")

    
"""

   The main function starts here.

"""


def main(): 
    create_dir(ROOT_DIR)
    parse_packet('t.pcap') 
    kml_file()
    new=1
    url="https://www.google.com/maps/d/splash?app=mp"
    webbrowser.open(url,new=new)


main()   
   
