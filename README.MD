# Remy the RAT

### A stealth RAT (Remote Access Tool) for use on Linux/Windows/Unix/OSX

![](https://www.artifex.co.il/he/wp-content/uploads/2024/11/DALL·E-2024-11-27-10.56.51-A-large-chubby-and-angry-rat-wearing-a-white-chefs-hat-standing-upright-with-its-arms-crossed-in-a-defiant-pose.-The-rat-has-a-scruffy-gray-fur-co.webp)

This tool allows remote control over a Linux/Windows/Unix/OSX machine by using any REST based file storage such as AWS S3 as a C2 server.

This is how it works:
1. The service decides on a DNS record to query based on the current date and the data in this file (DGA)
2. The service queries that DNS record (TXT) to get the root URL
3. The service sends a HTTP/S GET request to that URL to get the encrypted commands list
4. The service decrypts the commands list (hybrid RSA+AES256) with a hard-coded private key
5. Each command from the commands list contains the URL to which the service will report its execution status via an HTTP/S PUT request for an encrypted status report (hybrid RSA+AES256 with pre-shared, hard-coded public key)
6. The service generates a file which contains the list of command IDs which were already executed to avoid executing the same command twice
7. The service sleeps for 60 seconds and looks for new commands...

### Utils
You can use the following utils to maintain and manage your little RATs pen:
- utils/dga-calc.py - Will print the DNS TXT record that the RAT will try to access today and tomorrow and the one that will be successfully chosen today. If you want the RAT to start using today's or tomorrow's DNS record you can register it now.
- utils/keys-generator.py - You can use that tool to generate two sets of key sets, one for the commands list and another for the commands outputs. After doing so remember to update the hard coded keys (private key for decrypting commands list and public key for encrypting commands outputs).
- utils/decryptor.py - Can decrypt the commands list or commands outputs files just like Remy does/expects it
- utils/encryptor.py - Can encrypt the commands outputs or commands list files just like Remy does/expects it

### Installation/Deployment
- Make sure you have Python 3 installed
- Install all the required packages listed in `requirements.txt` file
- Run the remy.py file as the user you would like it to run as a service

Happy cooking! <3!