"""
====================================================================
                                                   __      
                                                 o'')}_____@
    HM? DID I HEAR PORT SNIFFER? HM.   *shnifsh*  ^_/      ) 
                                                  (_(_/-(_/

---------------------------------------------------------------------  
Port Sniffer by Hashing! Bless you~  (and Pansy)
Usage: python pansy.py <hostname|ip|ip-range|network> <ports> <udp|tcp>

Instructions:
> Default ports are set to be the top 1000 common ports for both udp and tcp.
> You may use ranges for both ip and ports.
> Example usage for a udp scan at port 1-1000: python hmap.py google.com 1-1000 udp
> You will get the following: list of open ports (UDP and/or TCP),
                              service name/banner (if available),
                              OS (if detectable)
> Give our resident sniffer, Pansy, some treats and pets.
> UDP scan still a bit wonky when giving a range of ports.
"""

import socket
import sys
import netaddr
import msvcrt
import time
from datetime import datetime

from scapy.all import *
from concurrent.futures import *
import os
os.environ['MANUF'] = '/usr/share/wireshark/manuf'
FNULL = open(os.devnull, 'w')
conf.verb = 0 
common_tcp_ports = [1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389]
udp_payloads = {53: b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00',  123: b'\xE3\x00\x04\xFA\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00', 161: b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x1b\x02\x04\x71\xb4\x85\x1f\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00'}


def scan_tcp(target_host, ports_to_scan):
    print(f"Pansy started to sniff TCP ports on {target_host}... She is getting sadder and sadder each time.")
    open_ports = []
    open_svcs = []
    banner =[]
    
    if isinstance(ports_to_scan, int):
        p_scan = [ports_to_scan]
    else:
        p_scan = ports_to_scan
    total = len(p_scan)
    
    def scan_port(port):
        try:
            socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_tcp.settimeout(3)
            error = socket_tcp.connect_ex((target_host, port))
            
            if error == 0:
                try:
                    socket_tcp.send(b"Hello\r\n")
                    banner_recv = socket_tcp.recv(2048)
                    ban_decode = banner_recv.decode('utf-8').split(" ")
                    banner.append(ban_decode[0])
                                
                except:
                    banner.append("")
                
                return port
            socket_tcp.close()
        except Exception as e:
            print("Pansy: Wait a minute, I need a scritch. Call me again later. (ERROR) {}".format(e))

    try:
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_port, port): port for port in p_scan}
            
            for i, future in enumerate(as_completed(futures)):
                if msvcrt.kbhit(): 
                    key = msvcrt.getch()
                    if key: 
                        progress = ((i + 1) / total) * 100
                        print("Pansy: HM. PLS BE PATIENT, I AM {:.2f}% OF THE WAY!!! >:(".format(progress))

                port = future.result()
                if port:
                    try:
                        open_svcs.append(socket.getservbyport(port))
                    except:
                        open_svcs.append("unknown")
                    open_ports.append(port)
    except Exception as e:
         print("Pansy: Wait a minute, I need a scritch. Call me again later. (ERROR): {}".format(e))

    if open_ports:
        print(f"Pansy: EWWO AM BACK. Here are the open TCP ports on {target_host}:")
        indent = "    "
        print(str(indent))
        print(str(indent) + "TCP PORTS".ljust(5) + str(indent) + "SERVICE".ljust(5) + str(indent) + str(indent)+ "BANNERS".ljust(5))
        for open, svcs,ban in zip(open_ports, open_svcs,banner):
            print("{}{}/tcp{}{}{}{}{}".format(indent,str(open).rjust(5),indent,svcs.ljust(5),indent,indent,ban.rjust(10)))
        print(str(indent))
    else:
        print(f"Pansy: EWWO AM BACK. No open TCP ports found on {target_host}. Wer my treats? Hm. :<")

def scan_udp(target_host,ports_to_scan):
    print(f"Pansy is working overtime. Now sniffing UDP ports on {target_host}...")
    open_ports = []
    open_filtered_ports = []
    open_svcs = []
    banner =[]
    
    if isinstance(ports_to_scan, int):
        p_scan = [ports_to_scan]
    else:
        p_scan = ports_to_scan
    total = len(p_scan)
    def scan_port_udp(port):
        try:
            socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            payload = udp_payloads.get(port, b'')
            socket_udp.settimeout(3)
            socket_udp.sendto(payload, (target_host, port))
            rcvd, addr = socket_udp.recvfrom(1024)
            if rcvd != None:
                open_ports.append(port)
                try:
                    rcvd.decode('utf-8').split(" ")
                except:
                    open_svcs.append("unknown")
        
        except socket.timeout:
            open_filtered_ports.append(port)           
        except Exception as e:
            #print("scan port error Pansy: Wait a minute, I need a scritch. Call me again later. (ERROR) {}".format(e))
            pass
    try:
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(scan_port_udp, port): port for port in p_scan}
            
            for i, future in enumerate(as_completed(futures)):
                if msvcrt.kbhit(): 
                    key = msvcrt.getch()
                    if key: 
                        progress = ((i + 1) / total) * 100
                        print("Pansy:I am UnDerPayed!!! BE PATIENTSH PLSH. but hehe: {:.2f}%".format(progress))

    except Exception as e:
         print(" thread error Pansy: Wait a minute, I need a scritch. Call me again later. (ERROR): {}".format(e))
    indent = "    "

    if open_ports or open_filtered_ports:
        print(f"Pansy: EWWO AM BACK. Here are the open UDP ports on {target_host}:")
        print(str(indent))
        print(str(indent) + "UDP PORTS".ljust(5) + str(indent) + "SERVICE".ljust(5) + str(indent) + str(indent))
        
    if open_ports:
        for open, svcs, ban in zip(open_ports, open_svcs, banner):
            print("{}{}/udp{}{}{}{}{}".format(indent, str(open).rjust(5), indent, svcs.ljust(5), indent, indent, ban.rjust(10)))
        print(str(indent))

    if open_filtered_ports:
        for open_f in open_filtered_ports:
            print("{}{}/udp{}{}".format(indent, str(open_f).rjust(5),indent, str("open|filtered")))
        print(str(indent))
    
    else:
        print(f"Pansy: EWWO AM BACK. No open UDP ports found on {target_host}. Wer my treats? Hm. :< (You can use --givetreats command!)")
    
    print("")

def os_detect(target_host):
    try:
        rcvd = sr1(IP(dst=str(target_host))/UDP()/DNS(rd=1,qd=DNSQR(qname="www.google.com")),timeout = 2)
        ttl = rcvd.ttl
        if 0 < ttl <= 64:
            print("Pansy: HM. I also got shomething sho I am guesshing the OS is Linux/Unix. Hm. I shound shmart.")
        elif 64 < ttl <= 128:
            print("Pansy: HM. I shniffed our neighbors' window and a piece of paper got stucked: \"The OS is Windows\" ")
        else:
            print("Pansy: HM? Plsh interpret thish for me, I'm tired: TTL = {}".format(ttl))

    except:
        print("Pansy: HM? WHAT OS? GIVE ME MORE TREATS.")   
        pass     

def get_ip():
    target_host = sys.argv[1]
    if '-' in target_host:
        ip_start, ip_end = target_host.split("-")
        if "." not in ip_end:
            octet1, octet2, octet3, _ = ip_start.split(".")
            ip_end ="{}.{}.{}.{}".format(octet1,octet2,octet3, ip_end)
        ip_range = netaddr.IPRange(ip_start, ip_end)

    elif '/' in target_host:
        ip_range = list(netaddr.IPNetwork(target_host))
        ip_range = ip_range[1:-1]

    else:
        try:
            ip_range = [socket.gethostbyname(target_host)]
        except:
            print(f"Cannot resolve {target_host}")
            sys.exit(1)

    return ip_range

def get_port_tcp():
    if len(sys.argv) == 2 or sys.argv[2] == "udp" or sys.argv[2] == "tcp":
        ports = common_tcp_ports
    elif (len(sys.argv) == 3 or len(sys.argv) == 4) and sys.argv[2] != "udp" and sys.argv[2] != "tcp":
        port_input = sys.argv[2]
        if '-' in port_input:
            port_start, port_end = port_input.split("-")
            ports = range(int(port_start),int(port_end)+1)
        else:
            ports= int(port_input)
    
    return ports

def get_port_udp():
    if len(sys.argv) == 2 or sys.argv[2] == "udp" or sys.argv[2] == "tcp":
        ports = [53,69,123,161]
    elif len(sys.argv) == 4:
        port_input = sys.argv[2]
        if '-' in port_input:
            port_start, port_end = port_input.split("-")
            ports = range(int(port_start),int(port_end)+1)
        else:
            ports = int(port_input)
    
    return ports

def main():
    dog = """
====================================================================
                                                   __      
                                                 o'')}_____@
    HM? DID I HEAR PORT SNIFFER? HM.   *shnifsh*  ^_/      ) 
                                                  (_(_/-(_/

---------------------------------------------------------------------  
Port Sniffer by Hashing! Bless you~  (and Pansy)
Usage: python pansy.py <hostname|ip|ip-range|network> <ports> <udp|tcp>

Instructions:
> Default ports are set to be the top 1000 common ports for both udp and tcp.
> You may use ranges for both ip and ports.
> Example usage for a udp scan at port 1-1000: python hmap.py google.com 1-1000 udp
> You will get the following: list of open ports (UDP and/or TCP),
                              service name/banner (if available),
                              OS (if detectable)
> Give our resident sniffer, Pansy, some treats and pets.
> UDP scan still a bit wonky when giving a range of ports.
        """
    if len(sys.argv) < 2:
        print(dog)
        sys.exit(1)
        
    else:
        banner ="""
------------------------------------------------------------------------
       __           _____        _____     __________/ o \/\_________     
     o'')}_____@   |o o o|* * *  |::  |. .| []  []  []  []|o| # # #  |. 
      ^_/      )  HM? MY TIME TO SHNIFF?  | []  []  []    |o| # # #  |.
      (_(_/-(_/    |_[]__|__[]___|_||_|__<|____________;;_|_|___/\___|_.
                   ====================================================
------------------------------------------------------------------------  
Port Sniffer by Hashing! Bless you~ (and Pansy)
Usage: python pansy.py <hostname|ip|ip-range|network> <ports> <udp|tcp>
For help: python pansy.py

You may press any key to check progress of the scan!
"""
    if len(sys.argv) > 1 and "--givetreats" not in sys.argv:
        print(banner)
        ip_addresses = get_ip()

        try:
            if ("tcp" in sys.argv and "udp" not in sys.argv) or len(sys.argv) == 2 or (len(sys.argv) == 3 and sys.argv[2] != "udp" and sys.argv[2] != "tcp"): 
                for ip in ip_addresses:
                    scan_tcp(str(ip), get_port_tcp())
                    os_detect(ip)
                    print(f"---------------------------------------------------------------------")
                    print("")

            if "udp" in sys.argv:
                for ip in ip_addresses:
                    scan_udp(str(ip), get_port_udp())
                    os_detect(ip)
                    print(f"---------------------------------------------------------------------")
                    print("")

        except Exception as e:
            print("Pansy: Hm? I don't undershtand but I think itsh ur fault. (An error occured. Check input.)")
            pass
        
        now = datetime.now()

        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
        print("Wer my treats? Hm. :< (You can use --givetreats command!)")
        print("[Panshy Port Shcan idkth Secondsary: {}]".format(dt_string))
        
    elif "--givetreats" in sys.argv:
        dog_treat = """
                                 
                              &&&&&&&&&&&&       
                            %&//     //(((&%     
                         &&&//((       ///((     
          &&&&&        &%(((((  //@@@     @@&&&  
        &&#####&%&     &&###((////   ((@@@((&&&  
     &%%#####((///%%&%&%%%%####&%/  /(*^*((&%&  
  .&&%%%((///,,&%&(///((&&&&&&&//   //   &&    hm. thanks. pero pakisubo naman.     
     (((//   &&(((,(((,,///           %&&            pagod na nga ko dito oh, hm.
  .&&///(((((&&,,,,,,,,,,,,,,       ,,(((&&     
  .&%(((((///((   ,,,,,,         ,,,,,///&%     
     &&%//&&%//,,, ,,,     ,,  ,,,,,//(((&&     
        %&&&%//,,,,///,,,,,,,,,,,///((%&&                 _               _       
             &&,,,(&&&&&&&&//,,((&&&((&&&		 (_'-------------'_)       
             %%(((%        %%((%%   %%%%%  	         (_.=============._)         
               &%&&          &&&&        
              """
        print(dog_treat)       
        askuser = input("Will you feed pansy the treat? (y/n)")
        if askuser == "Y" or askuser =="y":
            print(":>")
        else:
            print(":<")
            time.sleep(2)
            print(">:(")

if __name__ == "__main__":
    main()

