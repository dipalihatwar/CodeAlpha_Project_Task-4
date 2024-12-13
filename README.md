# CodeAlpha_Project_Task-4
# Network-Based Intrusion Detection System(NIDS)
A Network Intrusion Detection System (NIDS) is a cybersecurity tool that observes and examines network activity to identify potential threats or breaches. By continuously monitoring data flow, it can detect unusual patterns or suspicious behavior that may signal a security issue. The system examines data packets as they travel through the network and uses predefined rules or behavioral analytics to recognize known attack methods and unusual activities. NIDS can identify threats such as unauthorized access, denial-of-service attacks, and harmful data transmissions, helping to protect the network from various cyber risks.
This project demonstrate the setup of a network based intrusion detection system using suricata to monitor and analyze network traffic.
  
  •TOOL USE: suricata 
  
  •FEATURES : 
    
    -Real-time network traffic analysis
    
    -Logging and alerting mechanisms

 •INSTALLATION:
 
  STEP 1: start your kali linux
  
  STEP 2: Update Kali Linux:
  Before installing Suricata, update and upgrade your Kali Linux system
 
  sudo apt update
  
  sudo apt upgrade -y
 
  STEP 3: Install Suricata: sudo apt install suricata -y
  ![Screenshot 2024-12-12 163123](https://github.com/user-attachments/assets/66b49428-17e6-4f70-837e-08c1cf355259)
 
  STEP 4: Verify Installation: suricata --version
  ![Screenshot 2024-12-12 171102](https://github.com/user-attachments/assets/cd4048e6-7ed6-4cd9-a44f-dc338ac7e286)

  STEP 5: Configure Network Interface: Suricata needs to know which network interface to monitor
 
  ip a
 
  STEP 6: Edit Suricata Configuration:
 
  Suricata’s configuration file is located at /etc/suricata/suricata.yaml
 
  -Set the correct interface:
    
    af-packet:
    interface: eth0
    
  -Set the HOME_NET Variable:
    
    home-net:
    192.168.0.127/24
   ![Screenshot 2024-12-12 171336](https://github.com/user-attachments/assets/985b6fae-b55c-4be9-a0b2-46322a777459)

  -Enable EVE JSON Output:
     
      outputs:
      
       eve-log:
       enabled: yes
       filetype: regular 
       filename: /var/log/suricata/eve.json

    STEP 7:Set Up Suricata Rules:
  
   - update suricata:
      sudo suricata-update
     ![Screenshot 2024-12-12 171220](https://github.com/user-attachments/assets/eb7bfeb7-85e1-4c26-bb4a-b2635f4fbe97)

  -Create Custom Rules:You can also add your custom detection rules.
     sudo nano /etc/suricata/rules/local.rules
     ![Screenshot 2024-12-12 171529](https://github.com/user-attachments/assets/135eb06c-23ed-4d9c-9d81-bbb759e5e4ae)

  -Detect ICMP Echo Request (Ping):
    
    alert icmp any any -> $HOME_NET any (msg:"ICMP Echo Request"; itype:8; sid:1000001;)

  -Detect HTTP SQL Injection Attempt:
    
    alert http $EXTERNAL_NET any -> $HOME_NET 80 (msg:"SQL Injection Attempt"; content:"' OR 1=1 --"; http_uri; sid:1000002;)

  STEP 8: Start Suricata to Monitor Traffic: 
    
     sudo suricata -c /etc/suricata/suricata.yaml -i eth0

  STEP 9: Check the Suricata Logs:
    
    cat /var/log/suricata/eve.json
    

