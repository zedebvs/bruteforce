from utils import md5_hash, sha1_hash, bcrypt_verify, argon2_verify, clear
from multiprocessing import Process, Manager, Queue
import datetime, time
import os
from itertools import product
from CONFIG import Parameters
from hardcode import parse_char_pool, line_, print_, settings_symbols, settings_symbols, log_hash
import numpy as np

class SymbolsBrute():
    def __init__(self, param: Parameters):
        self.param = param
        
    def bruteforce(self):
        symbols_pool = "".join(parse_char_pool(self.param.symbols))
        found_results = []
        log_entries = []
        targets_alg = None
        
        attack_map = {
        "md5":    {"worker": process_prefix_chunk, "func": md5_hash},
        "sha1":   {"worker": process_prefix_chunk, "func": sha1_hash},
        "bcrypt": {"worker": process_prefix_chunk_verify,   "func": bcrypt_verify},
        "argon2": {"worker": process_prefix_chunk_verify,   "func": argon2_verify},
        }

        while targets_alg is None:
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
        alg_list = attack_map.get(name_alg)
        
        
        clear()
        line_("Начало атаки на хэши посимвольным перебором")
        prefix_chunks = np.array_split(list(symbols_pool), self.param.cores)
        try:
            with Manager() as manager:
                shared_targets = manager.list(targets_alg.get('targets'))
                log_queue = manager.Queue()
                proc = [Process(target=alg_list.get("worker"), args=(chunk, symbols_pool, self.param.password_leng, shared_targets, log_queue, self.param.chunk_size,alg_list.get("func"),self.param.verbose)) for chunk in prefix_chunks]
                start = datetime.datetime.now()
                log_entries.append(f"Начало атаки: {start}")
                log_entries.append(settings_symbols(self.param.cores, self.param.password_leng, self.param.output, "".join(parse_char_pool(self.param.symbols)), targets, name_alg))
                for p in proc: p.start()
                
                while any(p.is_alive() for p in proc) or not log_queue.empty():
                    while not log_queue.empty():
                        found_item = log_queue.get()
                        found_results.append(found_item)
                        hash_val, pwd = list(found_item.items())[0]
                        log_line = print_(f"Спустя {datetime.datetime.now() - start} был найден хэш: {hash_val} из строки: {pwd}")
                        log_entries.append(log_line.strip())
                        targets.discard(hash_val)

                    if not shared_targets: 
                        for p in proc:
                            if p.is_alive():
                                p.terminate() 
                        break
                    time.sleep(0.1) 

                for p in proc: p.join() 

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
        
            
def process_prefix_chunk(prefix_chunk, full_alphabet, max_len, shared_targets, log_queue, chunk_size,hash_function, verbose=False):
    if verbose: print(f"Процесс: {os.getpid()} работает с символами: {''.join(prefix_chunk)}")
    
    targets_local = set(shared_targets)
    batch = []
                
    for prefix in prefix_chunk:
        for i in range(max_len):
            for p in product(full_alphabet, repeat=i):
                password = prefix + "".join(p)
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
                    targets_local = set(shared_targets)
                if not targets_local:
                    return 
    return

def process_prefix_chunk_verify(prefix_chunk, full_alphabet, max_len, shared_targets, log_queue, chunk_size, hash_verify, verbose=False):
    if verbose: print(f"Процесс: {os.getpid()} работает с символами: {''.join(prefix_chunk)}")
    
    targets_local = set(shared_targets)
    batch = []
                
    for prefix in prefix_chunk:
        for i in range(max_len):
            for p in product(full_alphabet, repeat=i):
                password = prefix + "".join(p)
                for _hash in targets_local:
                    if hash_verify(password, _hash):
                        try:
                            shared_targets.remove(_hash)
                            log_queue.put({_hash: password})
                            targets_local.discard(_hash)
                        except ValueError:
                            pass
                batch.append(password)
                if len(batch) >= chunk_size:
                    batch.clear()
                    targets_local = set(shared_targets)
                if not targets_local:
                    return 
    return