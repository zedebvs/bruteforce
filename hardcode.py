def line(STRING, list_:list):
    ln = "-"*30+STRING+"-"*30
    for i in list_:
        ln +=f"\n{i}"
    return ln + "\n" + "-"*(60 + len(STRING))

def parse_char_pool(symbol_ranges):
    chars = []
    for r in symbol_ranges:
        chars.extend([chr(i) for i in range(r['start'], r['end']) if chr(i) not in chars])
    return chars

def lists(lists: list):
    ln = ''
    for i in lists:
        ln += f"\n{i}"
    if ln == '':
        ln = '\nПусто'
    return ln

def log_hash(hashes):
    f_ = '\n'
    for i in hashes:
        f_ += f'{i}\n'
    return f_

def disp(cores, output, verbose, chunk_size, password_leng, symbols, wordlissts, rainbows, md5, sha1, bcrypt, argon2):
    print(f"""Количество ядер: {cores}\nФайл для вывода: {output}\nИнтерактивный режим: {verbose}\nРазмер чанка: {chunk_size}\nДлина пароля: {password_leng}\nСимволы: {''.join(parse_char_pool(symbols))}\nДоступные радужные листы: {lists(wordlissts)}\nДоступные вордлисты: {lists(rainbows)}\nТаргеты:\n{line('md5', md5)}\n{line('sha1', sha1)}\n{line('bcrypt', bcrypt)}\n{line('argon2', argon2)}""")


def line_(STRING):
    print("-"*50)
    print(STRING)
    print("-"*50)

def print_(STRING):
    print(STRING)
    return STRING + '\n'

def settings_symbols(cores, password_length, output, symbols, targets, alg):
    return f'{"-"*50}\nИспользуемые параметры:\n{line(alg, targets)}\nКоличество процессов: {cores}\nДлина целевой строки: {password_length}\nФайл вывода: {output}\nПул символов: {symbols}\n{"-"*50}'


def settings_lists(cores, output, targets, alg, type_, list_):
    return f'{"-"*50}\nИспользуемые параметры:\n{line(alg, targets)}\nКоличество ядер: {cores}\nТип листа: {type_}\nИспользуемый лист: {list_}\nФайл вывода: {output}\n{"-"*50}'