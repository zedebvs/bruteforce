from utils import md5_hash, sha1_hash, bcrypt_verify, argon2_verify, clear
from multiprocessing import Process, Manager
import datetime, time
import os
from CONFIG import Parameters
from hardcode import line_, print_, settings_lists,lists, log_hash
from tqdm import tqdm

class WordlistBrute:
    def __init__(self, param: Parameters):
        self.param = param
        self.attack_map = {
            "md5":    {"worker": process_wordlist_chunk, "func": md5_hash},
            "sha1":   {"worker": process_wordlist_chunk, "func": sha1_hash},
            "bcrypt": {"worker": process_wordlist_chunk_verify, "func": bcrypt_verify},
            "argon2": {"worker": process_wordlist_chunk_verify, "func": argon2_verify},
        }

    def bruteforce(self):
        found_results = []
        log_entries = []
        wordlist_path = None 
        targets_alg = None
        
        while wordlist_path is None:
            clear()
            file = str(input(f"Доступные листы для атаки:\n{lists(self.param.discover_files('texts_file'))}\nИмя файла:"))
            if file in self.param.texts_file.get('file_names'):
                wordlist_path = os.path.join(self.param.texts_file.get('dir'), file) 
            
        while targets_alg is None:
            clear()
            choice = str(input("Алгоритм:\n1 - md5\n2 - sha1\n3 - bcrypt\n4 - argon2\n5 - все\n6 - выход\n"))
            if choice == '1':
                targets_alg = self.param.sha1
            if choice == '2':
                targets_alg = self.param.md5
            if choice == '3':
                targets_alg = self.param.bcrypt
            if choice == '4':
                targets_alg = self.param.argon2
            if choice == '5':
                pass
            if choice == '6':
                break
            
        name_alg = targets_alg.get("name")
        targets = set(targets_alg.get("targets"))
        alg_config = self.attack_map.get(name_alg)
        
        file_size = os.path.getsize(wordlist_path)
        chunk_size = file_size // self.param.cores


        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            total_lines = sum(1 for line in f)

        clear()
        line_(f"Начало атаки по словарю: {wordlist_path}")
        try:
            with Manager() as manager:
                shared_targets = manager.list(targets)
                log_queue = manager.Queue()
                processes = []
                progress_queue = manager.Queue() 

                for i in range(self.param.cores):
                    start_byte = i * chunk_size
                    end_byte = (i + 1) * chunk_size if i < self.param.cores - 1 else file_size
                    
                    p = Process(target=alg_config["worker"], args=(wordlist_path, start_byte, end_byte, shared_targets, log_queue, progress_queue, alg_config["func"], self.param.chunk_size, self.param.verbose))
                    processes.append(p)
                    p.start()
                    
                start = datetime.datetime.now()
                log_entries.append(f"Начало атаки: {start}")
                log_entries.append(settings_lists(self.param.cores, self.param.output, targets, name_alg, "wordlist", wordlist_path))
                
                with tqdm(total=total_lines, unit= ' Паролей', desc=f'Алгоритм {name_alg}') as pbar:
                    while any(p.is_alive() for p in processes) or not log_queue.empty() or not progress_queue.empty():
                            
                            if self.param.verbose:
                                while not progress_queue.empty():
                                    pbar.update(progress_queue.get())
                            
                            while not log_queue.empty():
                                found_item = log_queue.get()
                                found_results.append(found_item)
                                hash_val, pwd = list(found_item.items())[0]
                                message = f"Спустя {datetime.datetime.now() - start} был найден хэш: {hash_val} из строки: {pwd}"
                                pbar.write(message)
                                log_entries.append(message)
                                targets.discard(hash_val)

                            if not shared_targets: 
                                for p in processes:
                                    if p.is_alive():
                                        p.terminate() 
                                break
                            time.sleep(0.1) 

                for p in processes: p.join()
        except KeyboardInterrupt:
            print("[-] Принудительное завершение атаки.")
                
        end_time = datetime.datetime.now()
            
        if not found_results or len(found_results) < len(targets_alg.get("targets")):
            log = f"Атака закончилась, не все хэши найдены\nВремя выполнения: {end_time - start} секунд\nОставшиеся хэши: {log_hash(targets)}"
            log_entries.append(log)
            line_(log)
        else:
            log = f"Атака закончилась успешно, все хэши найдены\nВремя выполнения: {end_time - start} секунд"
            log_entries.append(log)
            line_(log)
        
        log_entries.append(f"Конец атаки: {end_time}\n\n\n\n\n")
        self.save_result("\n".join(log_entries))
        input("Для продолжения нажмите Enter...")
            
    def save_result(self, output_):
        with open(self.param.output, 'a') as f:
            f.write(output_)
        print(f"[+] Результат сохранен в файл: {self.param.output}")

def process_wordlist_chunk(filepath, start_byte, end_byte, shared_targets, log_queue, progress_queue, hash_function, chunk_size, verbose=False):
    #if verbose: print(f"Процесс: {os.getpid()} работает с байтами от {start_byte} до {end_byte}")
    targets_local = set(shared_targets)
    batch = []
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        f.seek(start_byte)
        if start_byte > 0:
            f.readline()

        while f.tell() < end_byte and targets_local:
            password = f.readline().strip()
            if not password:
                continue
            
            _hash = hash_function(password)
            if _hash in targets_local:
                try:
                    shared_targets.remove(_hash)
                    log_queue.put({_hash: password})
                    targets_local.discard(_hash)
                except ValueError:
                    pass
            
            batch.append(password)
            if len(batch) >= chunk_size:
                batch.clear()
                if verbose: progress_queue.put(chunk_size)
                targets_local = set(shared_targets)

def process_wordlist_chunk_verify(filepath, start_byte, end_byte, shared_targets, log_queue, progress_queue, verify_function, chunk_size, verbose=False):
    #if verbose: print(f"Процесс: {os.getpid()} работает с байтами от {start_byte} до {end_byte}")
    targets_local = list(shared_targets)
    batch = []
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        f.seek(start_byte)
        if start_byte > 0:
            f.readline()

        while f.tell() < end_byte and targets_local:
            password = f.readline().strip()
            if not password:
                continue

            for target_hash in list(targets_local):
                if verify_function(password, target_hash):
                    try:
                        shared_targets.remove(target_hash)
                        log_queue.put({target_hash: password})
                        targets_local.remove(target_hash)
                    except ValueError:
                        pass
            
            batch.append(password)
            if len(batch) >= chunk_size:
                batch.clear()
                if verbose: progress_queue.put(chunk_size)
                targets_local = list(shared_targets)