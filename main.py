from CONFIG import Parameters
from brute_sumbol import SymbolsBrute
from brute_lists import WordlistBrute
from utils import clear

params = Parameters()
symbols = SymbolsBrute(params)
lists = WordlistBrute(params)

#params.display()



def main():
    while True:
        clear()
        choice = str(input("Выберите режим\n1 - Символьный перебор\n2 - Перебор листами\n3 - Просмотреть настройки\n4 - Выход\n"))

        if choice == "1":
            symbols.bruteforce()
            input("Нажмите Enter для продолжения...")
        if choice == "2":
            lists.bruteforce()
            input("Нажмите Enter для продолжения...")
        if choice == "3":
            params.display()
            input("Нажмите Enter для продолжения...")
        if choice == '4':
            break

if __name__ == "__main__":
    main()