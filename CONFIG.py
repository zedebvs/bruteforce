from utils import *
import sys
from hardcode import disp
import os
from multiprocessing import current_process


CONFIG_NAME = 'CONFIG.json'


class StaticConfig:
    
    def __init__(self, config_path=CONFIG_NAME):
        self.conf_data = load_data(config_path)
        if self.conf_data is None:
            print("[!] Критическая ошибка: не удалось загрузить CONFIG.json. Завершение работы.", file=sys.stderr)
            sys.exit(1)

        self.cores: int = self.conf_data.get('cores', 1)
        self.output: str = self.conf_data.get('output')
        self.verbose: bool = self.conf_data.get('verbose', False)
        self.chunk_size: int = self.conf_data.get('chunk_size', 10000)
        self.password_leng: int = self.conf_data.get('password_leng', 6)
        self.symbols: list = self.conf_data.get('symbols', [])
        self.rainbow: dict = self.conf_data.get('rainbow')
        self.texts_file: dict = self.conf_data.get('texts_file')

        self.algs: dict = {alg['name']: alg for alg in self.conf_data.get('algs', [])}
        self.md5: dict = self.algs.get('md5')
        self.sha1: dict = self.algs.get('sha1')
        self.bcrypt: dict = self.algs.get('bcrypt')
        self.argon2: dict = self.algs.get('argon2')

        #print(f"[+] Начальные настройки загружены из {CONFIG_NAME}")
    
    
class Parameters(StaticConfig):
    def __init__(self):
         
        super().__init__()
        
        if current_process().name == "MainProcess":
            try:
                self.setup()
            except Exception:
                pass
        else:
            pass
                
    def setup(self):
        os.makedirs(self.rainbow.get('dir'), exist_ok=True)
        os.makedirs(self.texts_file.get('dir'), exist_ok=True)
        
    def optimal_reset(self):
        self.cores = os.cpu_count()
        self.output = 'output.txt'
        self.chunk_size = 10000
        self.password_leng = 6
        self.symbols = [{"start": 97, "end": 123}]
        self.save()
        
    def save(self):
        self.conf_data = {
            'cores': self.cores,
            'output': self.output,
            'verbose': False,
            'chunk_size': self.chunk_size,
            'password_leng': self.password_leng,
            'symbols': self.symbols,
            'rainbow': self.rainbow,
            'texts_file': self.texts_file,
            'algs': [
                self.md5,
                self.sha1,
                self.bcrypt,
                self.argon2
            ]
        }
        
        save_data(CONFIG_NAME, self.conf_data)
    
    def discover_files(self, info_key: str) -> list:
        files = []
        info = getattr(self, info_key)
        directory_to_scan = info.get('dir')

        if not directory_to_scan or not os.path.isdir(directory_to_scan):
            print(f"[!] Директория для {info_key} не найдена или не указана. Поиск файлов пропущен")
            info['file_names'] = []
            return []
        for root, dirs, filenames in os.walk(directory_to_scan):
            for filename in filenames:
                if filename.endswith('.txt'):
                    files.append(filename)

        info['file_names'] = files
        return files
    
    def display(self):
        clear()
        disp(self.cores, 
             self.output, 
             self.verbose, 
             self.chunk_size, 
             self.password_leng, 
             self.symbols, 
             self.discover_files('rainbow'), 
             self.discover_files('texts_file'), 
             self.md5.get('targets'), 
             self.sha1.get('targets'), 
             self.bcrypt.get('targets'), 
             self.argon2.get('targets'))
        self.save()