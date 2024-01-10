# IPsec
To successfully transfer file from sender to receiver
gcc sender.c -o sender
./sender file.txt

gcc gatway_server.c -o gatway_server -lcrypto
./gatway_server 0

gcc gatway_client.c -o gatway_client -lcrypto
./gatway_client

gcc receiver.c -o receiver
./receiver

Instruction
1]To sender file provide file name the file which we want to transmit to receiver as command line argument

2]This part we want to show successful transmission so enter 'o' as no attack

3]now execute gatway server file with 0 as command line to indicate no attack

4]wait for until server started shows at gatway sever after that run gatway_client file

5]wait for a 1 minute and finally execute receiver file

At host decrypted_file will contain the data transfer by sender

2]For sender attack
gcc sender.c -o sender
./sender file.txt

gcc gatway_server.c -o gatway_server -lcrypto
./gatway_server 0

gcc attack_server_sender.c -o attack_server_sender
./attack_server_sender


Instruction
1]To sender file provide file name the file which we want to transmit to receiver as command line argument
2]provide 1 at sender to generate attack
3]now execute gatway_server file  and provide 0 for this attack is not gatway attack
4]now wait for minute and execute attack file

At attack you can see thigs capture between sender and gatway1


2]For gatway attack

gcc sender.c -o sender
./sender file.txt

gcc gatway_server.c -o gatway_server -lcrypto
./gatway_server 1

gcc gatway_client.c -o gatway_client -lcrypto
./gatway_client

gcc attack_client_gatway.c -o attack_client_gatway
./attack_client_gatway




Instruction
1]To sender file provide file name the file which we want to transmit to receiver as command line argument
2]provide 0 at sender as it is not sender attack
3]now execute gatway_server file  and provide 1 for this attack is gatway attack
4]wait for until server started shows at gatway sever after that run gatway_client file
5]now run attacker file 
Now you can see things capture by attacker 




IPsec/IPSec files at main · arbaj459/IPsec
