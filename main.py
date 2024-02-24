from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from email.mime.multipart import MIMEMultipart
from os import path, remove, makedirs, walk
from Crypto.Random import get_random_bytes
from email.mime.text import MIMEText
import matplotlib.pyplot as plt
from datetime import datetime
from io import BytesIO
import pandas as pd
import schedule
import smtplib
import hashlib
import base64
import string
import random
import time
import re

def ask_new_username():
    def verify_username(username):
        with open('data/users.txt', 'r') as f:
            content = f.read().split()
        for c in content:
            if username == c.split(" -|- ")[0]:
                return False
        return True
    username = input("Please, insert an username: ")
    flag = verify_username(username)
    if flag:
        return username
    else:
        print("The username already exist, select a new username")
        return ask_new_username()

def ask_new_password():
    def verify_password(password):
        if len(password) < 8:
            print("The password is too short.")
            return False
        if not re.search(r'[a-z]', password):
            print("The password has no lower case character")
            return False
        if not re.search(r'[A-Z]', password):
            print("The password has no upper case character")
            return False
        if not re.search(r'[0-9]', password):
            print("The password has no number")
            return False
        if not re.search(r'[!@#$%^&*()\-_=+{};:,<.>]', password):
            print("The password has no special character (!@#$%^&*()\-_=+{};:,<.>).")
            return False
        return True
    password = input("Please, insert a valid password.\nMinimum requirements:\n    - At least 8 characters\n    - One lower case and one upper case character\n    - One number\n    - One special character(!@#$%^&*()\-_=+{};:,<.>)\nInsert password: ")
    flag = verify_password(password)
    if flag:
        return password
    else:
        return ask_new_password()

def ask_time():
    try:
        time = int(input('How often do you want a verification to be done?\nInsert the number of minutes: ')) 
        return time
    except:
        print('The time must be a whole number.')
        return ask_time()

def ask_email():
    def verify_email(email):
        match = re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)
        if not match:
            return False
        
        try:
            with smtplib.SMTP('smtp.office365.com', 587) as server:
                server.set_debuglevel(0)
                server.verify(email)
                server.quit()
                return True
        except:
            return False
    try:
        email = input("Please, insert an email account: ")
        flag = verify_email(email)
        if flag:
            return email
        else:
            print("Error: Invalid email")
            return ask_email()
    except ValueError:
        print("Error: Invalid email")
        return ask_email()
    
def ask_hash():
    hash_algorithms = ["SHA-256", "SHA-1", "MD-5"]
    try:
        hash_algorithm = int(input("Which hash algorithm so you prefer:\n    1. SHA-256 (Most secure)\n    2. SHA-1\n    3. MD-5 (Least secure)\nPlease insert the number of the algorithm selected: "))
        if hash_algorithm in [1,2,3]:
            return hash_algorithms[hash_algorithm-1]
        else:
            print("Error: Please, insert a valid number (1, 2, 3).")
            return ask_hash() 
    except ValueError:
        print("Error: Please insert a number (1, 2, 3).")
        return ask_hash() 
    
def ask_number_hash():
    try:
        number = int(input("How many messages digests would you like? (Between 1 (Least secure), 2 and 3 (Most secure)): "))
        if number in [1,2,3]:
            return number
        else:
            print("Error: Please, insert a valid number (1, 2, 3).")
            return ask_number_hash() 
    except ValueError:
        print("Error: Please insert a number (1, 2, 3).")
        return ask_number_hash()    
    
def ask_folder():
    folder_path = input("Please, insert the path to the folder you want to check: ")
    folder_path = folder_path.replace('\\', '/')
    if path.isdir(folder_path):
        return folder_path
    else:
        print("Error: Invalid folder path")
        return ask_folder()

def password_to_bytes(password):
    new_bytes = password.encode('utf-8')
    bytes_256 = hashlib.sha256(new_bytes).digest()
    return bytes_256

def register():
    key = get_random_bytes(32)
    username = ask_new_username()
    password = password_to_bytes(ask_new_password())
    encrypted_key1 = encrypt(key, password)
    encrypted_key2 = encrypt(key, password)
    email = ask_email()
    algorithm = ask_hash()
    n_algorithm = ask_number_hash()
    folder = ask_folder()
    with open('data/users.txt', 'a') as f:
            f.write(username+" -|- "+encrypted_key1+" -|- "+encrypted_key2+" -|- "+email+" -|- "+algorithm+" -|- "+str(n_algorithm)+" -|- "+folder+"\n")
    return True, key, username, email, algorithm, str(n_algorithm), folder
    
def ask_password():
    password = input("Please, insert your password: ")
    return password

def ask_username():
    username = input("Please, insert your username: ")
    return username

def login():
    username = ask_username()
    password = password_to_bytes(ask_password())
    with open('data/users.txt', 'r') as f:
        content = f.read().split('\n')
    for c in content:
        c = c.split(' -|- ')
        if c[0] == username:
            try:
                key1 = decrypt(c[1], password)
                key2 = decrypt(c[2], password)
                if key1 == key2:
                    return False, key1, c[0], c[3], c[4], c[5], c[6]
                else:
                    print('The password or the username is wrong')
                    return login()
                break
            except:
                print('The password or the username is wrong')
                return login()
    print("This username does not exist")
    return login()

def ask_connection():
    try:
        number = int(input("Do you want to start a new HIDS or continue with an old one?\n    1. New HIDS\n    2. Continue old HIDS\nInsert the number: "))
        if number == 1:
            return register()
        elif number == 2:
            return login()
        else:
            print("Error: Please, insert a valid number (1, 2).")
            return ask_connection() 
    except ValueError:
        print("Error: Please insert a number (1, 2).")
        return ask_connection()

def createHash(input_string, algorithm):
    if algorithm == "SHA-256":
        hash_object = hashlib.sha256(input_string)
        hash_digest = hash_object.digest()
    elif algorithm == "SHA-1":
        hash_object = hashlib.sha1(input_string)
        hash_digest = hash_object.digest()
    elif algorithm == "MD-5":
        hash_object = hashlib.md5(input_string)
        hash_digest = hash_object.digest()
    else:
        return 'The algorithm is incorrect'
    base64_encoded_hash = base64.b64encode(hash_digest)
    base64_string = base64_encoded_hash.decode('utf-8')
    return base64_string

def encrypt(data, key):
    if isinstance(data, str):
        data = data.encode()
    iv = get_random_bytes(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

def decrypt(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data

def backup(dir_file, dir_backup, key): 
    with open(dir_file, 'rb') as f:
        content = f.read()
    encrypted_content = encrypt(content,key)
    with open(dir_backup, 'x') as f:
        f.write(encrypted_content)
    
def newFile(dir_file, username, algorithm_hash, num_hash, key):
    def generate_random_path(extension):
        section_number = str(random.randint(1, 8))
        directory_number = str(random.randint(1, 8))
        subfolder_letter = random.choice('abcdefgh')
        file_name = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        folder_path = "data/backup/directory" + directory_number + "/section" + section_number + "/" + subfolder_letter
        file_path = folder_path + "/" + file_name + "." + extension
        if not path.exists(folder_path):
            makedirs(folder_path, exist_ok=True)
        return file_path
    with open(dir_file, 'rb') as f:
        contenido = f.read()
    extension = dir_file.split(".")[-1]
    filename = dir_file.split("/")[-1]
    if filename.split('.')[0] == '':
        filename = 'nameless.' + extension 
    parent_folder = dir_file.split("/")[-2]
    dir_backup = generate_random_path(extension)
    encrypted_dir_file = encrypt(dir_file, key)
    encrypted_dir_backup = encrypt(dir_backup, key)
    dir_folder_hash = 'data/hash/' + username + "/" + extension + "/"+ filename[0]
    if not path.exists(dir_folder_hash):
        makedirs(dir_folder_hash, exist_ok=True)
    dir_hash = dir_folder_hash + "/" + filename.split(".")[0] + "_" + parent_folder + '.txt'
    if path.exists(dir_hash):
        with open(dir_hash, 'a') as f:
            f.write('\n\n--|--' + encrypted_dir_file+ '--|--')
    else:
        with open(dir_hash, 'x') as f:
            f.write('--|--' + encrypted_dir_file + '--|--')
    for _ in range(int(num_hash)):
        salt = str(random.randint(10, 99))
        encrypted_salt = encrypt(salt, key)
        new_hash = createHash(contenido + salt.encode('utf-8'), algorithm_hash) + ' -|- ' + encrypted_dir_file + ' -|- ' + encrypted_dir_backup + ' -|- ' + encrypted_salt
        if not path.exists(dir_folder_hash):
            makedirs(dir_folder_hash, exist_ok=True)
        if path.exists(dir_hash):
            with open(dir_hash, 'a') as f:
                f.write('\n' + new_hash)
        else:
            with open(dir_hash, 'a') as f:
                f.write(new_hash)
    backup(dir_file, dir_backup, key)
    
def addErrorLog(dir_file, username):
    date_path = datetime.now()
    logname = str(date_path.month) + "-" + str(date_path.year) + ".log"
    dir_log_folder = "data/logs/" + username + "/"
    if not path.exists(dir_log_folder):
        makedirs(dir_log_folder, exist_ok=True)
    dir_log = dir_log_folder + logname
    if not path.exists(dir_log):
        with open(dir_log, 'x') as f:
            f.write("- There was an incident in the file: "+ dir_file + ". Detected on: " +date_path.strftime('%d/%m/%Y') + ".")
    else:
        with open(dir_log, 'a') as f:
            f.write("\n- There was an incident in the file: "+ dir_file + ". Detected on: " +date_path  .strftime('%d/%m/%Y') + ".")

def addLog(username):

    date_path = datetime.now()
    logname = str(date_path.month) + "-" + str(date_path.year) + ".log"
    dir_log_folder = "data/logs/" + username + "/"
    if not path.exists(dir_log_folder):
        makedirs(dir_log_folder, exist_ok=True)
    dir_log = dir_log_folder + logname
    if not path.exists(dir_log):
        with open(dir_log, 'x') as f:
            f.write("+ There was no incident. Verified on: " +date_path.strftime('%d/%m/%Y') + ".")
    else:
        with open(dir_log, 'a') as f:
            f.write("\n+ There was no incident. Verified on: " +date_path.strftime('%d/%m/%Y') + ".")

def restoreFile(dir_file, dir_backup, key):
    if path.exists(dir_file):
        remove(dir_file)
    with open(dir_backup, 'rb') as f:
        content = f.read()
    decrypted_content = decrypt(content, key)
    with open(dir_file, 'x'):
        pass
    with open(dir_file, 'wb') as f:
        f.write(decrypted_content)

def restoreHash(dir_hash, dir_file, dir_backup, algorithm_hash, num_hash, key):
    with open(dir_hash, 'r') as f:
        hash_codes = f.readlines()
    i=0
    while i<len(hash_codes):
        length = len(hash_codes[i].split('--|--'))
        if length == 3: 
            file = hash_codes[i].split('--|--')[1]
            decrypted_file = decrypt(file, key).decode('utf-8')
            if decrypted_file == dir_file:
                hash_code = []
                for j in range(1, int(num_hash)+1):
                    hash_code.append(hash_codes[i+j])
                break
        i+=1
    with open(dir_backup, 'rb') as f:
        backup = f.read()
    decrypted_backup = decrypt(backup, key)
    new_hash_code = []
    for h in hash_code:
        parts = h.split(' -|- ')
        encrypted_dir_file = parts[1]
        encrypted_dir_backup = parts[2]
        encrypted_salt = parts[3]
        salt = decrypt(encrypted_salt, key)
        new_hash = createHash(decrypted_backup + salt, algorithm_hash)
        new_h = new_hash + ' -|- ' + encrypted_dir_file + ' -|- ' + encrypted_dir_backup + ' -|- ' + encrypted_salt
        new_hash_code.append(new_h)
    for j in range(1, int(num_hash)+1):
        hash_codes[i+j] = (new_hash_code[j-1])
    with open(dir_hash, 'w') as f:
        f.writelines(hash_codes)

def verify(dir_file, username, email, algorithm_hash, num_hash, key):
    res = False
    with open(dir_file, 'rb') as f:
        contenido = f.read()
    filename = dir_file.split("/")[-1].split(".")[0]
    if filename == '':
        filename = 'nameless'
    extension = dir_file. split('.')[-1]
    parent_folder = dir_file.split("/")[-2]
    dir_hash = 'data/hash/' + username + '/' + extension + "/" + filename[0] + "/" + filename + "_" + parent_folder + '.txt'
    if path.exists(dir_hash):
        with open(dir_hash, 'r') as f:
            hash_codes = f.read().split("--|--")
        i=1
        found = False
        while i<len(hash_codes):
            file = hash_codes[i]
            decrypted_file = decrypt(file, key).decode('utf-8')
            if decrypted_file == dir_file:
                hash_code = hash_codes[i+1].split("\n")
                found = True
                break
            i+=2
        if found:
            for h in hash_code:
                if not h == '':
                    h = h.split(" -|- ")
                    code = h[0]
                    salt = h[-1]
                    decrypted_salt = decrypt(salt, key)
                    new_hash = createHash(contenido + decrypted_salt, algorithm_hash)
                    if not code == new_hash: 
                        dir_backup = h[-2]
                        decrypted_dir_backup = decrypt(dir_backup,key).decode('utf-8')
                        addErrorLog(dir_file, username)
                        restoreHash(dir_hash, dir_file, decrypted_dir_backup, algorithm_hash, num_hash, key)
                        restoreFile(dir_file, decrypted_dir_backup, key)
                        sendIncidentEmail(dir_file, email)
                        res = False
                        break
                    else:
                        res = True
        else:
            print(dir_file)
            newFile(dir_file, username, algorithm_hash, num_hash, key)
            res = 'New file'
    else:
        print("++"+dir_file)
        newFile(dir_file, username, algorithm_hash, num_hash, key)
        res = 'New file'
    return res

def sendIncidentEmail(dir_file, email):
    sender_email = "insegus.ssii4@hotmail.com"
    receiver_email = email
    password = "Insegus4@"
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = "Incident on " + datetime.now().strftime("%d/%m/%Y") + "."
    body = "An incident has been detected on the file: " + dir_file + ".\nThe file has been restored succesfully from the last backup saved."
    message.attach(MIMEText(body, 'plain'))
    with smtplib.SMTP('smtp.office365.com', 587) as server:
        server.starttls()
        server.login(sender_email, password)
        text = message.as_string()
        server.sendmail(sender_email, receiver_email, text)
        
def sendMonthlyEmail(email, username):
    def generate_bar_chart(logs):
        data = {}
        incidents = 0
        for l in logs:
            day = "Day " + l.split()[-1].split("/")[-3]
            if l.split()[0] == '-':
                if day in data.keys():
                    data[day] =  data[day] + 1
                else:
                    data[day] = 1
                incidents += 1
            else:
                if day not in data.keys():
                    data[day] = 0
            
        df = pd.DataFrame(list(data.items()), columns=['Day', 'Count'])
    
        fig, ax = plt.subplots(figsize=(10,   5))
        ax.bar(df['Day'], df['Count'])
        ax.set_ylabel('Incident count')
        ax.set_title("Month's summary")
        
        img = BytesIO()
        fig.savefig(img, format='png')
        img.seek(0)
        img_base64 = base64.b64encode(img.getvalue()).decode('utf-8')
        plt.close(fig)
        
        return img_base64, incidents, len(data.keys())
    date = datetime.now()
    logname = str(date.month) + "-" + str(date.year) + ".log"
    dir_log = "data/logs/" + username + "/" + logname
    sender_email = "insegus.ssii4@hotmail.com"
    receiver_email = email
    password = "Insegus4@"
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = date.strftime("%B") + "'s monthly report from Insegus."
    
    if path.exists(dir_log):
        with open(dir_log, 'r') as f:
            content = f.read()
        logs = content.split("\n")
        chart, incidents, days = generate_bar_chart(logs)
        if incidents != 0:
            body = """
            <html>
                <head>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                        }
                        h2 {
                            color: #333333;
                        }
                        p {
                            margin-bottom: 10px;
                        }
                    </style>
                </head>
                <body>
                    <h2>Verifications have been carried out for """ + str(days) + """ days.</h2>
                    <h2>This month there have been found """ + str(incidents) + """ incidents.</h2>
                    <p>All files have been restored successfully from the last backups saved.</p>
                    """ + """<img src="data:image/png;base64,""" + chart + """" alt="Bar Chart">
                </body>
            </html>
            """
        else:
            body = "Verifications have been carried out for " + days + " days.\nThis month there was no incident, all data is unaltered."
    else:
        body = "There was no verifications this month."
    message.attach(MIMEText(body, 'html'))
    with smtplib.SMTP('smtp.office365.com', 587) as server:
        server.starttls()
        server.login(sender_email, password)
        text = message.as_string()
        server.sendmail(sender_email, receiver_email, text)

def main():
    def do_verify():
        res = True
        num = 0
        new_files = 0
        for root, _, files in walk(folder):
            for file in files:
                dir_file = path.join(root, file)
                dir_file = dir_file.replace("\\", "/")
                check = verify(dir_file, username, email, algorithm, n_algorithm, key)
                if check == False:
                    res = False
                elif check == 'New file':
                    new_files = new_files + 1
                else:
                    num = num + 1
        if res:
            addLog(username)
            print(str(num) + ' succesfully verified')
        else:
            print('There were errors detected')
        if new_files > 0:
            print(str(new_files) + ' new files registered')
    def send_monthly_email():
        sendMonthlyEmail(email, username)
    new_user, key, username, email, algorithm, n_algorithm, folder = ask_connection()
    time_period = ask_time()
    if new_user:
        num = 0
        for root, _, files in walk(folder):
            for file in files:
                dir_file = path.join(root, file)
                dir_file = dir_file.replace("\\", "/")
                newFile(dir_file, username, algorithm, n_algorithm, key)
                num = num + 1
        print('Succesfully registered')
        print(str(num) + ' new files registered')
    else:
        do_verify()
    schedule.every(time_period).minutes.do(do_verify)
    schedule.every(30).minutes.do(send_monthly_email)
    
    while True:
        schedule.run_pending()
        time.sleep(1)
    
if __name__ == "__main__":
    main()