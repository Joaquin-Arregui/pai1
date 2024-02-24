import os
import random
import schedule
import time

def test_add_random_byte_file(root_dir):
    file_list = []
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            file_list.append(os.path.join(dirpath, filename))
    if file_list:
        random_file = random.choice(file_list)
        with open(random_file, 'rb+') as file:
            content = file.read()
            random_bit = random.randint(0, 1)
            content += bytes([random_bit])
            file.seek(0)
            file.write(content)

def test_add_random_byte_hash(root_dir):
    file_list = []
    for dirpath, _, filenames in os.walk('data/hash/jarrdi'):
        for filename in filenames:
            file_list.append(os.path.join(dirpath, filename))
    if file_list:
        random_file = random.choice(file_list)
        with open(random_file, 'r+') as f:
            content = f.readlines()
        new_content = []
        for c in content:
            if len(c.split(' -|- ')) > 1:
                random_string = random.randint(0, 99)
                c = str(random_string) + c
            new_content.append(c)
        f.writelines(new_content)
        
def test1(root_dir):
    def test():
        test_add_random_byte_file(root_dir)
    schedule.every(30).seconds.do(test)
    
    while True:
        schedule.run_pending()
        time.sleep(1)

def test2(root_dir):
    def test():
        test_add_random_byte_hash(root_dir)
    schedule.every(30).seconds.do(test)
    
    while True:
        schedule.run_pending()
        time.sleep(1)

def test3(root_dir):
    def test():
        test_add_random_byte_file(root_dir)
        test_add_random_byte_hash(root_dir)
    schedule.every(30).seconds.do(test)
    
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__": 
    directorio_raiz = 'C:/Users/Joaquin/Desktop/a/Universidad/Cuarto/SSII/prueba2'
    test3(directorio_raiz)