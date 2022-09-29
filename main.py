from encryption import *

def main():
    while(True):
        print("1. Generate RSA")
        print("2. Generate signature")
        print("3. Validate signature")
        print("4. Encrypt")
        print("5. Decrypt")
        print("6. Exit")
        print("\n")

        choice = input("Select task: ")
        if choice == "1":
            generateRSA()
        elif choice == "2": 
           generateSign()
        elif choice == "3":
            validateSign()
        elif choice == "4":
            encrypt()
        elif choice == "5":
            decrypt()
        else:
            exit()