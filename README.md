Download Link: https://assignmentchef.com/product/solved-cs6262-project-4-network-monitoring
<br>






<strong>Goals:</strong>

The goal of this project is to introduce students to the techniques that help to differentiate malicious and legitimate network traffic. This is a task that network operators perform frequently. In this project, the students are provided with samples of malicious and legitimate traffic. They can observe how each type of traffic looks like. In the project folder, there is a pcap file that contains network traffic that originates from multiple hosts in the same network. This pcap file is a mixture of legitimate and malicious traffic. The students are asked to investigate the pcap file in network tools such as WireShark. Finally, the students are asked to use Snort and write their own Snort rules, which will differentiate malicious and legitimate traffic.

In summary, the students are introduced to:

<ul>

 <li>Observing pcap samples of legitimate and malicious network traffic</li>

 <li>Using Snort and writing Snort rules to differentiate legitimate traffic from malicious traffic</li>

</ul>

<strong>Figure 1: </strong><em>Network setup for traffic collection.</em>

<strong>Definitions and Traffic Collection Set-up:</strong>

In this assignment, there are four attack scenarios. For each attack, a scenario is defined based on the implemented network topology, and the attack is executed from one or more machines outside the target network. Figure 1 shows the implemented network, which is a common LAN network topology on the AWS computing platform. The hosts are behind a NAT, and their IP addresses belong to a single /16:

172.31:0:0:/16.  It also shows a visual representation of the network and our traffic collection set-up.

<strong>Types of attacks:</strong>

<ul>

 <li><strong>Denial of Service (DoS):</strong></li>

</ul>

In DoS, attackers usually keep making full TCP connections to the remote server. They keep the connection open by sending valid HTTP requests to the server at regular intervals but also keep the sockets from closing. Since any Web server has a finite ability to serve connections, it will only be a matter of time before all sockets are used up and no other connection can be made.

<em>It is your task to find out how the DoS attack is present in the </em>evaluation <em>pcap given to you.</em>

<ul>

 <li><strong>Bruteforce:</strong></li>

</ul>

<strong>FTP</strong>/<strong>SSH </strong>is attacked via a Kali Linux machine( the attacker machine), and Ubuntu 14.0 system is the victim machine. There is a large dictionary that contains 90 million words that were used for the list of passwords to brute force.

<em>It is your task to identify which one of them is present in the </em>evaluation <em>pcap given to you.</em>

<ul>

 <li><strong>Web Attacks:</strong></li>

</ul>

There are 3 possible web attacks, one of which would be present in your pcap.

<ul>

 <li>DVWA-based: Damn Vulnerable Web App (DVWA) is a PHP/MySQL web application that is vulnerable. An attacker might try to hijack it.</li>

 <li>XSS-based: An attacker might try to launch an XSS attack.</li>

 <li>SQL Injection: An attacker might try an SQL injection attack.</li>

</ul>

<em>It is your task to identify which ones of them are present in your </em>evaluation <em>pcap.</em>

<ul>

 <li><strong>Botnet</strong>:</li>

</ul>

<strong>Zeus </strong>is a trojan horse malware that runs on Microsoft Windows. It might be presented in the pcap. It can be used to carry out many malicious and criminal tasks and it is often used to steal banking information by man-in-the-browser keystroke logging and form grabbing. It is used to install the Crypto-Locker ransomware as well. Zeus spreads mainly through drive-by downloads and phishing schemes. <strong>The Ares botnet </strong>might also be presented in the pcap. It is an open-source botnet and has the following capabilities:

<ul>

 <li>remote cmd.exe shell</li>

 <li>persistence</li>

 <li>file upload/download</li>

 <li>screenshot (e) keylogging</li>

</ul>

<em>Either Zeus and Ares could be present in your </em>evaluation <em>pcap, it is your task to identify which one.</em>

<strong>Notes</strong>: the traffic doesn’t have to cover all the attacks, and they can also cover multiple attacks for one category. For example, for web attacks, we can have both SQL injection and XSS. You need to find those in the evaluation pcap.

<strong>Sample traffic: </strong>For each type of traffic mentioned above, we provide a sample of that category/type of traffic. These samples are only for <strong>illustration </strong>purposes. These samples are <em>only examples</em>, and they are <strong>not </strong>the same as the actual traffic that is included in the evaluation pcap, which the students will need to label.

<ul>

 <li><strong>Legitimate background traffic:</strong></li>

</ul>

For this exercise, we assume normal traffic to include HTTP, DNS. An example of normal (attack free) traffic can be found in:

<ul>

 <li>pcap <strong>● BruteForce:</strong></li>

</ul>

○    sample_bruteforce_ssh.pcap

○    sample_bruteforce_ftp.pcap <strong>● Botnet:</strong>

The host generates this traffic <em>explicitly </em>to communicate with a C&amp;C server. The host communicates with the C&amp;C server to receive commands, updates, <em>etc.</em>

○    sample_bot.pcap <strong>● Web Attack:</strong>

○    sample_web.pcap ○      sample_xss.pcap

○    sample_sqlinjection.pcap.

You should use multiple rules to cover all these attacks.

<ul>

 <li><strong>dos:</strong>

  <ul>

   <li>We do <strong>not </strong>provide a sample. Please look at the example Snort rules on dos in the resources section.</li>

  </ul></li>

</ul>

<strong>Introduction Video (optional):</strong>

We made a short video about wireshark and the project(about 15 mins): <a href="https://bluejeans.com/s/EiWzm3BxScx/">https://bluejeans.com/s/EiWzm3BxScx/</a>

You will need to log in with your GaTech login information. When viewing the video, please slide right at the bottom of the screen to see the second screen in full screen mode.

We recommend that you read over the project description before viewing the video.

There are probably more filters(such as the filtering on the http method etc) that you can apply. We encourage you to read over the wire shark related links at the end of the project description to learn more about it.

<strong>Project Tasks (</strong><strong>100 </strong><strong>points):</strong>

The goal is to:

<ul>

 <li>Explore the given pcaps in Wireshark and identify the attack traffic patterns.</li>

 <li>Write Snort rules to raise alerts to identify the attacks.</li>

</ul>

<strong><em>Towards this goal, please follow the tasks below:</em></strong>

<ul>

 <li><strong>Install Wireshark </strong>in your local machine (we provide a VM but we recommend inspecting the pcaps via Wireshark on your local machine – instead of the VM as it is very CPU and RAM intensive).</li>

 <li><strong>Download</strong>: The vm from this <a href="https://drive.google.com/drive/folders/1zmGY0EgbY2GYHViKfCqx0nH5-uPDA6cQ?usp=sharing">link</a>.</li>

</ul>

In case you are doing the project on your local machine. We also provide the evaluation pcap in the link so you don’t need to scp it.

<strong>MD5 hash of 2021SP4.ova: ee14a57afceb03046a4e7f524b3aac12</strong>

<ul>

 <li><strong>Import </strong>the VM from this link. <strong>Login to the VM using: login: student, password: project4</strong></li>

 <li><strong>Locate </strong>the pcap files on your desktop. In this directory, you will find the sample pcaps and the evaluation pcap pcap.</li>

 <li><strong>Make observations </strong>on the pcaps:</li>

</ul>

Observe the sample pcaps to get an idea about how each type of malicious traffic looks like. You can use

Wireshark or tshark to isolate some traffic. For example, in Wireshark, you can apply display filters

<em>e.g. </em>tcp (to display only TCP traffic), ip.addr == 10.0.0.1 (to display traffic that originates from or is destined to this IP address). Also, you can combine filters using or/and.

You should use the attack descriptions above – to understand how these attacks should look like in network traffic.

<ul>

 <li><strong>Write Snort rules </strong>– keep in mind, we are using <strong>Snort3</strong>, and not Snort2 – please make sure you use the Snort version installed in the VM.</li>

</ul>

You can write your Snort rules in any file.  As an example, we’ll write them in ~/Desktop/eval.rules ●     You can now <strong>run these snort rules </strong>on the evaluation pcap using:

sudo snort -c /usr/local/etc/snort/snort.lua -r ~/Desktop/evaluation.pcap -R ~/Desktop/eval.rules -s 65535 -k none -l . (The result will be in `alert_json.txt`. The dot at the end means the result will be generated in the current directory)

Example Snort alert rule based on IP: alert tcp 10.0.0.1 any -&gt; any any (msg:”TCP traffic detected from IP 10.0.0.1″; GID:1; sid:10000001; rev:001;) It creates an alert message: TCP traffic detected from IP 10.0.0.1 when there is a TCP connection from the source IP 10.0.0.1 and any port to any destination IP and any destination port.

<ul>

 <li>You can then <strong>view the Snort alert </strong>log using sudo vim alert_json.txt.</li>

 <li><strong>Use </strong><strong>EXACTLY ONE of the following strings as the alert message in the Snort rule:</strong>

  <ol>

   <li><strong>DoS,</strong></li>

   <li><strong>Bruteforce,3. WebAttack,</strong></li>

   <li><strong> Botnet.</strong></li>

  </ol></li>

</ul>

For example, if you are writing a rule to detect ssh brute force, then the alert message should be “Bruteforce”. <strong>This will be used to grade your result – getting this part wrong can lead to a point loss.</strong>

<strong>Deliverable/Rubric:</strong>

For this project, you should submit <strong>two files</strong>

<ul>

 <li><strong>rules </strong>– your Snort rules file. You are not allowed to hardcode a single IP in their rules.</li>

</ul>

Instead, you should specify subnets and use the features of the attacks to capture them.

<ul>

 <li><strong>txt </strong>– the result file generated by running `python3 cal_unique_connection_2021.py alert_json.txt`. The script can be downloaded <a href="https://drive.google.com/file/d/1XPPfVpa3c3tWOE5njaOexBlreBHiyLNw/view?usp=sharing">here</a></li>

</ul>

Notes: Don’t zip the file. Just upload them as separate files. Make sure the filename is correct.

<strong>How to validate your answer:</strong>

<ol>

 <li>We consider a connection to be “src_ip:src_port:dest_ip:dest_port”. You can utilize the</li>

</ol>

`cal_unique_connection.py` to check the unique connections of your alert_json.txt. You can compare the number of Dos/BruteForce/WebAttack/Botnet you got with the statistics above. If the number is close, you are likely on the right track.

<ol start="2">

 <li>You can view the pcap file in Wireshark to confirm you are finding the right connections.</li>

 <li>Last, you can verify your result by submitting your answer to the gradescope (See steps 4&amp;5). As the number of trials is limited, perform step 2 first!</li>

 <li>We have provided you a way to verify your results on the Gradescope. You need to upload your <strong>txt </strong>and you will see your current score. Please note that this is only for you to verify the results and you still need to upload your result on canvas. And you can verify your results for <strong>at most</strong></li>

</ol>

<strong>10 times! </strong>Uploading more than 5 times in gradescope will tell you that you cannot verify your result anymore.

<ol start="5">

 <li>Running a single snort rule against the evaluation pcap can get a different result when you run it along with other snort rules. This is related to the limitation of Snort. So please run all your rules together to get the result we want.</li>

</ol>

<strong>Grading:</strong>

<ul>

 <li>The snort rules file you write would be run in the autograder.</li>

 <li>There are 4 attack categories as described above, each of which carries 25% grade weight.</li>

 <li>For each attack category, your grade = #correct alerts / (#real correct alerts + #incorrect alerts). Therefore, if you raise alerts for packets that are benign as one of the attack categories (false positives), you will lose points for that attack category. Also, if you miss raising an alert for an attack packet, you will lose points for that category.</li>

 <li>We will calculate your final grade for each category (which has 25 points as a full mark) by #final grade = min(25, #grade-for-one-category * 125%), which means if you catch <strong>80% </strong>of the attacks correctly, you can get full marks for the category.</li>

</ul>

<strong>Statistics for each type of unique connections (</strong><strong>Important!)</strong>:

<strong>Bruteforce: 3673</strong>

<strong>DoS: 8095</strong>

<strong>WebAttack: 40 Botnet: 47621</strong>

<strong>(The number might be a little different when you try to find it in Wireshark. Use the number that Snort gives you)</strong>

We consider a connection to be “src_ip:src_port:dest_ip:dest_port”. run  “<strong>python3</strong>

<strong>~/Desktop/cal_unique_connection_2021.py  yourAlertFile</strong>” to check the unique connections of your alert_json.txt and generate the results in `connections.txt`. If your alert JSON file is generated in the home directory, you might need to add sudo in front of your command.

<strong>FAQs</strong>

<ol>

 <li>Do I get partial credits if the snort rule is not 100% correct?</li>

</ol>

–       Partial credit is awarded according to how many false positives are detected. Please refer to the grading algorithm above.

<ol start="2">

 <li>Do you provide sample pcaps for dos?</li>

</ol>

–       No, we don’t provide sample pcaps for dos because you can observe dos from the evaluation pcap.  A good start is reading some existing snort rules for detecting dos attacks to get a sense of it.

<ol start="3">

 <li>Do we care about UDP packets?</li>

</ol>

-You can ignore UDP packets. You can look at UDP as well, but it won’t make much of a difference UDP is mostly for negotiation protocols/DNS, etc.

<ol start="4">

 <li>After grading this assignment, will you release the correct answers? -No, we don’t, since similar projects run across semesters.</li>

 <li>Should we ignore instances of ICMP and IP?

  <ul>

   <li>You can ignore ICMP &amp; IP</li>

  </ul></li>

 <li>Is Tshark/Wireshark installed on the virtual machine?

  <ul>

   <li>If the VM is too slow for you, I would recommend you install pcap reading tools on your local machine and use the VM only for Snort. evaluation.pcap is a very large file so it can take some time to load. You may need to increase the amount of RAM available to the system to get it to display properly.</li>

  </ul></li>

 <li>Looks like I can complete the assignment without using VM?</li>

</ol>

-Correct, you can complete without the VM but make sure your snort file works with the version installed in the given VM.

<ol start="8">

 <li>What constitutes a connection?</li>

</ol>

-A “Connection” is identified by its Source Address, Destination Address, Source Port, and Destination Port.

<ol start="9">

 <li>Any hints on what we should look for when trying to identify SPAM-ing? SMTP connections? -You may want to look at packets within a certain time frame.</li>

 <li>Can attacks be only from one or two machines or it should be from massive bot machines? -It can be from any number of machines. The exact number is not relevant.</li>

 <li>Should we include an IPV6 connection? or only IPV4? – Only IPV4</li>

 <li>We don’t need to zip the file when we submit right?</li>

</ol>

-No, you just need to submit the two files separately: eval.rules and connections.txt.

<ol start="13">

 <li>Is it possible to get 100% just using rules derived from samples?</li>

</ol>

-We can’t confirm or deny. &#x1f642;

The sample pcaps are there to give you a good idea, but we don’t claim they’re representative. You should learn the pattern in the sample pcap and try to find related or similar patterns in the evaluation pcap. Always manually verify that what you find is correct.

<ol start="14">

 <li>The instructions state “Do not use any preprocessors.” So that means we cannot use “flow” or “flowbits” in our rules because those keywords come from the Stream preprocessor. Correct?

  <ul>

   <li>You should not need flow or flowbits in this project.</li>

  </ul></li>

 <li>How can I make sure that I am not using a preprocessor?</li>

</ol>

-If you don’t change anything in your config file you will be fine.

<ol start="16">

 <li>I am getting some json error/json decoder error

  <ul>

   <li>Yes that means your json file is too big and maybe you need to put more constraints on your snort rule to generate a smaller json file.</li>

  </ul></li>

</ol>

<strong>Resources:</strong>

<strong>Readings on botnets behavior: </strong>Please read through the following papers, to get an understanding of what is a bot, and how botnets behave. Please note that we are not asking you to implement the proposed methodologies, <em>e.g. </em>a machine learning method to detect bots.

<ul>

 <li><em>”BotHunter: Detecting              Malware                Infection                Through                IDS-Driven           Dialog   Correlation”</em>,       Gu                         al. <a href="http://faculty.cs.tamu.edu/guofei/paper/Gu_Security07_botHunter.pdf">http://faculty.cs.tamu.edu/guofei/paper/Gu_Security07_botHunter.pdf</a></li>

 <li><em>”BotSniffer: Detecting Botnet Command and Control Channels in Network Traffic”</em>, G. Gu, J. Zhang, W. Lee, <a href="http://faculty.cs.tamu.edu/guofei/paper/Gu_NDSS08_botSniffer.pdf">http://faculty.cs.tamu.edu/guofei/paper/Gu_NDSS08_botSniffer.pdf</a></li>

 <li><em>”BotMiner: Clustering Analysis of Network Traffic for Protocol-and Structure-Independent Botnet</em></li>

</ul>

<em>Detection”</em>,                  G.                  Gu,                  R.                  Perdisci,                  J.                  Zhang,                  W.                  Lee,

<a href="https://www.usenix.org/legacy/event/sec08/tech/full_papers/gu/gu.pdf">https://www.usenix.org/legacy/event/sec08/tech/full_papers/gu/gu.pdf</a>

<strong>Snort resources: </strong>Here you can find some examples of Snort rules, and some resources so that you get familiar with Snort rules. The purpose of these resources is only to get you familiar with how Snort rules look like. You are expected to write your own Snort rules.

<ul>

 <li><a href="https://usermanual.wiki/Document/snortmanual.760997111/view">https://usermanual.wiki/Document/snortmanual.760997111/view</a></li>

 <li><a href="https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/000/596/original/Rules_Writers_Guide_to_Snort_3_Rules.pdf">https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/000/596/original/ </a><a href="https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/000/596/original/Rules_Writers_Guide_to_Snort_3_Rules.pdf">pdf</a></li>

</ul>

<strong>Example: Writing Snort rules to detect dos traffic: </strong>This is an example to give you an idea about how we can use our understanding of an attack, and write Snort rules with potentially long shelf life, to detect this attack. Intro reading for dos: <a href="https://en.wikipedia.org/wiki/Denial-of-service_attack">https://en.wikipedia.org/wiki/Denial-of-service_attack</a>. Snort for dos: Please read this to get a general idea about how Snort can be used for this purpose. Please focus on sections 3 and 4. <a href="http://www.ijeert.org/pdf/v2-i9/3.pdf">http://www.ijeert.org/pdf/v2-i9/3.pdf</a>. After reading the above, one way to detect dos traffic is to monitor the rate of incoming traffic. Here is an example Snort rule based on traffic rate:

<a href="http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node35.html">http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node35.html</a>

<strong>Useful tools/commands:</strong>

<ul>

 <li>You can SCP the files from the VM to your local machine and view them using Wireshark.</li>

 <li>SCP: <a href="http://www.hypexr.org/linux_scp_help.php">http://www.hypexr.org/linux_scp_help.php</a></li>

 <li>Redirecting a program’s output: <a href="http://linuxcommand.org/lc3_lts0070.php">http://linuxcommand.org/lc3_lts0070.php</a></li>

 <li>You can install Wireshark from here: <a href="https://www.wireshark.org/">https://www.wireshark.org/</a></li>

 <li>Wireshark display filters to view part of the traffic: <a href="https://wiki.wireshark.org/DisplayFilters">https://wiki.wireshark.org/DisplayFilters</a></li>

 <li>How to scp a file named file to the VM: scp file <a href="/cdn-cgi/l/email-protection" class="__cf_email__" data-cfemail="5221262736373c2612">[email protected]</a>&lt;VM’s ip&gt;:/home/student. If your VM has a different IP address than the above then you can find it by starting the VM, then log-in, and then do: ip a.</li>

 <li>The above scp command is just an example. Modify it accordingly. Resource for scp syntax: <a href="http://www.hypexr.org/linux_scp_help.php">http://www.hypexr.org/linux_scp_help.php</a></li>

</ul>

<strong>Subnet:</strong>

<ul>

 <li><strong>Why is 172.31.0.0/16 a subnet?</strong></li>

</ul>

Because it uses CIDR notation. CIDR and subnetting are virtually the same thing.

<ul>

 <li><strong>What’s CIDR?</strong></li>

</ul>

CIDR is Classless inter-domain routing. It is the /number representation.  In this case, we have /16 <strong>● What does /16 mean again?</strong>

/16 represents the <strong>subnet mask </strong>of 255.255.0.0

If you convert 255.255.0.0 into binary, you will see 16   1’s and that’s where the number 16 comes from. Of course, I can’t remember all those conversions for all netmask. There is a cheat sheet:

Wait, what’s a subnet mask?

Feel free to read this link if you want to know more: <a href="https://avinetworks.com/glossary/subnet-mask/">https://avinetworks.com/glossary/subnet-mask/</a>

<strong>Important Notes</strong>

<strong>Disclaimer for background traffic</strong>. Please note that the traffic that is found in the evaluation pcap, and/or at the Sample pcaps is not generated by us. The dataset closely resembles realist traffic. Part of this traffic might contain inappropriate content or language. We have taken extra measures and we have performed considerable effort to filter all traffic, based on commonly used inappropriate words. We have filtered the http payload and URIs. Nevertheless, it might still be possible that some inappropriate content or words might have not been filtered entirely. In case you locate such content, we are letting you know, that it is not intentional, and we are not responsible for it. Also, to complete this assignment, you do not need (nor do we ask you) to click on URLs found inside http payloads.

<strong>Additional tools are not allowed. </strong>For the assignment, you are not allowed to use any available tools, related to Snort or others. For example, you are not allowed to use Snort preprocessors that may be publicly available, pre-compiled Snort rules, detection tools. etc. <strong>You are expected to write your own Snort rules.</strong>