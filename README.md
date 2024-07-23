# SOAR-EDR-Project

# Objective
A virtual machine will be used as the environment to run LaZagne. LimaCharlie will detect the event and send out its details to Slack and email. Additionally, the user will be given a prompt on whether to isolate the machine or not. 
- LaZagne: program that retrieves passwords. 
- LimaCharlie: EDR (Endpoint Detection & Response) platform. Detect mailicous events and isolate machines
- Slack: Communications. receive alerts of the events
- Tine: SOAR (Security, Orchestration, Automation, Response) platform. Automate the workflow

# Diagram
Here is a diagram of what the playbook will showcase. It follows the objective and how the event flows throughout the whole process. The diagram is made in draw.io.
[Link to draw.io diagram in github](https://github.com/AlfonsoPajader/SOAR-EDR-Project/blob/main/SOAR%20EDR.drawio)

![image](https://github.com/user-attachments/assets/c032a70c-d8d5-48ee-88aa-dc7e73bbfde6)

# PreReq
Used a Windows VM to perform all the tasks. Did not use my personal computer.

# LimaCharlie Setup
>Make sure endpoint is connected and relaying events to LimaCharlie

1. In LimaCharlie, create your organization and go to Installation Keys, save the Sensor Key. Installation Key is used to enroll machines to LimaCharlie.
<img width="1512" alt="Screenshot 2024-07-21 at 5 25 10 PM" src="https://github.com/user-attachments/assets/fbab8084-dab3-4c00-8a47-a78a1110b21c">

2. At the bottom, copy the link that matches to your appropriate endpoint. This project uses a Windows 64 bit VM. 
<img width="1509" alt="Screenshot 2024-07-21 at 5 36 02 PM" src="https://github.com/user-attachments/assets/62331d1b-1887-4dbc-ae98-57cf17a0430b">

3. In the endpoint, paste download link and download.
<img width="1122" alt="Screenshot 2024-07-21 at 5 36 48 PM" src="https://github.com/user-attachments/assets/f1da20b8-4b85-4cbd-8812-a648fa97f44a">

4. Open an administrator powershell, go to the directory where the .exe file was downloaded, and run the command from the picture. *last part of command is your own unique sensor key*
<img width="976" alt="Screenshot 2024-07-21 at 5 43 16 PM" src="https://github.com/user-attachments/assets/c12b86e1-3abe-4d6a-8842-3672c329cda6">

5. Check to see if LimaCharlie is installed on the endpoint by going to Services and see if it's running.

6. Go to LimaCharlie sensors list, to ensure connection between EDR and endpoint. Sensors List is a list of all the enrolled machines.
<img width="1503" alt="Screenshot 2024-07-21 at 5 44 49 PM" src="https://github.com/user-attachments/assets/ae419620-c6ca-4d5c-9d8f-088462eaa93d">



# LaZagne and LimaCharlie (Detect & Respond) Rule

## LaZagne
1. Download [LaZgne](https://github.com/AlessandroZ/LaZagne). Will have to allow the program, as Windows will try to block it.
<img width="359" alt="Screenshot 2024-07-21 at 6 00 06 PM" src="https://github.com/user-attachments/assets/f78de59b-e086-47d5-9bad-ab3a5493771b">
2. Go back to PowerShell, and run the program
<img width="977" alt="Screenshot 2024-07-21 at 6 01 42 PM" src="https://github.com/user-attachments/assets/5ea91db3-efe4-4573-9049-8f231f012e2a">

## LimaCharlie (Detect & Response Rule)
3. Use the Timeline to find events to help create your rule. Look at exisiting rule and modify/build on it. Helps you with the format and field names.

<img width="1510" alt="Screenshot 2024-07-21 at 6 03 09 PM" src="https://github.com/user-attachments/assets/5fdedd29-2ced-4e2a-9b63-26033887d0d2">

4. Create the D&R Rule. If event detection hits criteria it will create a detection report.
Tip: search credential -> process creation -> copy raw and paste to new rule -> separate detect and respond
<img width="839" alt="Screenshot 2024-07-21 at 6 08 22 PM" src="https://github.com/user-attachments/assets/22145aba-4b32-4298-b7b1-abdd63614172">

detect
```
  events:
  - NEW_PROCESS
  - EXISTING_PROCESS
  op: and
  rules:
  - op: is windows
  - op: or
    rules:
    - case sensitive: false
      op: ends with
      path: event/FILE_PATH
      value: lazagne.exe
    - case sensitive: false
      op: ends with
      path: event/COMMAND_LINE
      value: all
    - case sensitive: false
      op: contains
      path: event/COMMAND_LINE 
      value: lazagne
    - case sensitive: false
      op: is
      path: event/HASH
      value: '3cc5ee93a9ba1fc57389705283b760c8bd61f35e9398bbfa3210e2becf6d4b05'
```

respond

```
- action: report
  metadata:
    author: MyDFIR
    description: Detects Lazagne (SOAR-EDR Tool)
    falsepositives:
    - To the moon
    level: medium
    tags:
    - attack.credential_access
  name: MyDFIR - HackTool - Lazagne (SOAR-EDR
```

5. Bottom of the screen click on "Target Event" and paste the given event from the timeline -> "Test Event." Also, check on LimaCharlie Detections to verify of event.
<img width="1499" alt="Screenshot 2024-07-21 at 7 41 06 PM" src="https://github.com/user-attachments/assets/9d5b215c-6d71-4832-a3c3-f6fec74335f2">

<img width="1507" alt="Screenshot 2024-07-21 at 7 45 20 PM" src="https://github.com/user-attachments/assets/f9ab3d18-748f-47d3-a981-95b6170ca9ec">

6. Cleaning up some of the data. Delete all previous detections within LimaCharlie Detection. Go back to computer run LaZagne all again. Go back to LimaCharlie and check new detections 

# Slack and Tines
> detection is showing up in tines 1:1 with limacharlie

## Slack 
1. Create a Slack account and a dedicated "alerts" channel.

## Tines
2. Place a webhook, Copy webhook url, Go back to LimaCharlie organization and go to "Outputs" -> "Add Outputs" -> Detections -> paste webhook url.
<img width="1511" alt="Screenshot 2024-07-21 at 9 42 25 PM" src="https://github.com/user-attachments/assets/73b7dbd8-c92a-4f57-bb7c-c6c0fae11cb3">

3. Generate another detection by running LaZagne again. Validate it in Tines webhook's events.
<img width="1512" alt="Screenshot 2024-07-21 at 9 44 59 PM" src="https://github.com/user-attachments/assets/3217532f-fc5e-4a12-858c-00e563c4f8b7">



# Full Tines (SOAR) Configuration
>send slack and email about detection information; then, generate user response on whether they should isolate the machine

## Sending nformation
### Adding Slack to Tines and its Credentials
1. More -> automations -> add Tines
2. Credentials -> new credentials -> slack -> use Tine's app for Slack -> allow permissions
3. Add slack template on to story with "send a message" 
<img width="1512" alt="Screenshot 2024-07-21 at 10 02 11 PM" src="https://github.com/user-attachments/assets/099ec0db-15bb-4a87-a033-36ad6973fe85">
4. Add Email, and your email information.
<img width="622" alt="Screenshot 2024-07-21 at 10 09 32 PM" src="https://github.com/user-attachments/assets/14b9f26f-e717-49e1-ae50-3331146592e9">
### slack
5. Right click on alerts channel to view details and copy channel id at the bottom.
6. Input channel id in Tines Slack.
7. Test by running the Slack rectangle, and check email if alert came in.
<img width="1182" alt="Screenshot 2024-07-21 at 10 11 26 PM" src="https://github.com/user-attachments/assets/34f4aafa-3e8e-4ede-8b2d-5d4055061adc">

## Responding to User Prompt page
In Tines story -> tools -> page -> drag it to the board
<img width="995" alt="Screenshot 2024-07-21 at 10 15 30 PM" src="https://github.com/user-attachments/assets/ff134f7a-8528-46b9-a8d2-e8da0ec1c1a9">

### Page
8. Add page to storyboard -> edit page - body detection information below 
<img width="392" alt="Screenshot 2024-07-23 at 10 47 12 AM" src="https://github.com/user-attachments/assets/f22a4569-b46c-4f7d-be56-04ace66a3c73">
#### detection - properties (fields were interested in)
Title: <<retrieve_detections.body.cat>> 
Time: <retrieve_detections.body.detect.routing.event_time>>
Computer: <<retrieve_detections.body.detect.routing.hostname>>
Source IP: <<retrieve_detections.body.detect.routing.int_ip>>
Username: <<retrieve_detections.body.detect.event.USER_NAME>>
File Path: <<retrieve_detections.body.detect.event.FILE_PATH>>
Command Line: <<retrieve_detections.body.detect.event.COMMAND_LINE>>
Sensor ID: <<retrieve_detections.body.detect.routing.sid>>
Detection Link: <<retrieve_detections.body.link>>

### Slack and Email 
9. Paste the variables in the message field. Add <Br> for linebrake when pasting onto email.
#### Email (html) line break
```
Title: <<retrieve_detections.body.cat>> 
<br>Time: <retrieve_detections.body.detect.routing.event_time>>
<br>Computer: <<retrieve_detections.body.detect.routing.hostname>>
<br>Source IP: <<retrieve_detections.body.detect.routing.int_ip>>
<br>Username: <<retrieve_detections.body.detect.event.USER_NAME>>
<br>File Path: <<retrieve_detections.body.detect.event.FILE_PATH>>
<br>Command Line: <<retrieve_detections.body.detect.event.COMMAND_LINE>>
<br>Sensor ID: <<retrieve_detections.body.detect.routing.sid>>
<br>
<br>Detection Link: <<retrieve_detections.body.link>>
```

### LimaCharlie
10. Access Management -> REST API -> copy Org JWT key to add limacharlie api to credentials
<img width="508" alt="Screenshot 2024-07-22 at 10 06 50 PM" src="https://github.com/user-attachments/assets/f65608c9-1ed7-4f9d-895e-280d6855298f">
11. Go back to story and add credential
this will allow LimaCharlie to work with the triggers

### Triggers 
12. Add Triggers. For Yes and No (yes=true, no=false)
![image](https://github.com/user-attachments/assets/2d9f38fd-7d45-4a30-8299-587cd7d8afa3)

13. Add HTTP Request to Isolate Sensor, followed by its status.
![image](https://github.com/user-attachments/assets/6587faa3-07e1-4246-9711-d792b30dad86)

![image](https://github.com/user-attachments/assets/fe98ae6e-2037-4b93-b1bc-00f4f93982f7)

14. Two more Slack boxes will be added to alert.
NO: ![image](https://github.com/user-attachments/assets/5866c76b-f6f6-4ac7-b7c2-78c2bdd647fe)

YES: ![image](https://github.com/user-attachments/assets/45aadfe2-e6db-4f18-bcc7-96e782c8e4b1)



# Running the whole process
<img width="555" alt="Screenshot 2024-07-23 at 10 39 08 AM" src="https://github.com/user-attachments/assets/5d589da2-6382-4f11-9e9f-23ebdf1aed2d">

1. Slack receives alert
<img width="1112" alt="Screenshot 2024-07-22 at 10 23 36 PM" src="https://github.com/user-attachments/assets/24dfa3eb-fd71-4a47-b805-7c3a50e6df09">
2. Email receives alert
<img width="1181" alt="Screenshot 2024-07-22 at 10 24 01 PM" src="https://github.com/user-attachments/assets/e19c280b-8ef3-4675-96b0-8dc5db9e3b8b">
3. User click on visit Page, and decides to isolate machine. After isolation, it just disconnected me from Microsoft Remote Desktop. Usually, it will stop allowing the endpoint from pinging to different destinations.

Slack:
<img width="1093" alt="Screenshot 2024-07-22 at 10 24 49 PM" src="https://github.com/user-attachments/assets/50b8f9cc-3747-4487-9599-013e713d1a97">

LimaCharlie:
<img width="474" alt="Screenshot 2024-07-22 at 10 25 15 PM" src="https://github.com/user-attachments/assets/efe79e50-7e01-460f-9242-97b5763daf1b">


# Conclusion
This project is able to combine an EDR and SOAR platform to automate the detection of a mailicious program. When LaZagne ran to retrieve passwords from the endpoint, a report was created because the event matched the EDR's rules. Now, with the SOAR platform connected with the EDR, it's able to mirror the event and send out the alert to our two communication channels: email and Slack. The user will see the alert and will able to decide on whether to isolate the endpoint or not. An isolated endpoint can no longer be reachable. After every prompt, it will send a updated reply of the situation. 

A diagram is really beneficial when creating your SOAR playbook because it helps visualize where the data is coming from. You will know it's start and it's intended destination. Having events is both a necessity and a hindirance. You will need events so you can simulate the whole playbook; certain sections can be validated. On the otherhand, having a lot of events is a hindirance because you can't focus on what's important. Therefore, I removed some of the sensors which greatly decreased my number of events.



