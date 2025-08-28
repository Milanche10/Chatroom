import threading
import os
import argparse
import socket
import sys
import tkinter as tk

class Send(threading.Thread):

    #Listens for users input from thread line

    #sock
    #name(str) : The user provided by user

    def __init__(self,sock,name):
        super().__init__()
        self.sock = sock
        self.name = name

    def run(self):
        #Listen for user input from command line and send it to the server
        #Typing "Quit" will close the connection and exit app

        while True:
            print('{}: '.format(self.name), end='')
            sys.stdout.flush()
            message = sys.stdin.readline()[:-1]

            #if we type "QUIT" we leave the chatroom

            if message == 'QUIT':
                self.sock.sendall('Server: {} has left the chat'.format(self.name).encode('ascii'))
                break

            #send message to server for broadcasting
            else:
                self.sock.sendall('{}: {}'.format(self.name, message).encode('ascii'))


        print('\nQuitting....')
        self.sock.close()
        os.exit(0)



class Receive(threading.Thread):

    #Listens for incoming messages from the server
    def __init__(self,sock,name):
        super().__init__()
        self.sock = sock
        self.name = name
        self.messages = None


    def run(self):
        #Recives data from the server and displays it in gui
        while True:
            message = self.sock.recv(1024).decode('ascii')

            if message:
                if self.messages:
                    self.messages.insert(tk.END, message)
                    print('hi')
                    print('\r{}\n{}: '.format(message, self.name), end='')

                else:
                    print('\r{}\n{}: '.format(message, self.name), end='')

            else:
                print('\n No. We have lost connection to the server')
                print('\nQuitting....')
                self.sock.close()
                os.exit(0)



class Client:

    #Menagment of client server connection and integration of GUI

    def __init__(self,host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.name = None
        self.messages = None

    def start(self):
        print('Trying to connect to {}:{}....'.format(self.host, self.port))
        self.sock.connect((self.host, self.port))

        print('Successfully connected to {}:{}\n'.format(self.host, self.port))


        self.name = input('Enter your name: ')

        print('\nWelcome {}, get ready to send and receive messages..'.format(self.name))

        #Create send and receive thread

        send = Send(self.sock, self.name)

        receive = Receive(self.sock, self.name)

        #start send and receive thread

        send.start()
        receive.start()

        self.sock.sendall('Server: {} has joined the chat. Say Hi'.format(self.name).encode('ascii'))
        print("\rReady! Leave the chatroom anytime buy typing 'QUIT'\n")
        print('{}: '.format(self.name), end='')

        return receive

    def send(self,textInput):
        #Send textInput data from the GUI
        message = textInput.get()
        textInput.delete(0, tk.END)
        self.messages.insert(tk.END, '{}: {}'.format(self.name, message).encode('ascii'))

        #Type "QUIT" to leave the chatroom
        if message == 'QUIT':
            self.sock.sendall('Server: {} has left the chat'.format(self.name).encode('ascii'))
            print('\nQuitting....')
            self.sock.close()
            os.exit(0)

        #SEND message to the server for broadcasting
        else:
            self.sock.sendall('{}: {}'.format(self.name, message).encode('ascii'))


def main(host, port):
    # Initialize and run GUI app
    client = Client(host, port)
    receive = client.start()

    window = tk.Tk()
    window.title('Chatroom')

    # Frame to hold the messages and scrollbar
    fromMessage = tk.Frame(master=window)
    fromMessage.grid(row=0, column=0, columnspan=2, sticky='nsew')

    scrollBar = tk.Scrollbar(master=fromMessage)
    scrollBar.grid(row=0, column=1, sticky='ns')  # Use `grid` instead of `pack`

    messages = tk.Listbox(master=fromMessage, yscrollcommand=scrollBar.set)
    messages.grid(row=0, column=0, sticky='nsew')  # Use `grid` instead of `pack`

    scrollBar.config(command=messages.yview)

    # Allow the messages frame to expand
    fromMessage.rowconfigure(0, weight=1)
    fromMessage.columnconfigure(0, weight=1)

    client.messages = messages
    receive.messages = messages

    # Frame for the text input and send button
    fromEntry = tk.Frame(master=window)
    fromEntry.grid(row=1, column=0, padx=10, sticky='ew')

    textInput = tk.Entry(master=fromEntry)
    textInput.pack(fill=tk.BOTH, expand=True)
    textInput.bind("<Return>", lambda x: client.send(textInput))
    textInput.insert(0, "Write your message here.")

    btnSend = tk.Button(master=window, text='Send', command=lambda: client.send(textInput))
    btnSend.grid(row=1, column=1, pady=10, sticky='ew')

    # Configure grid weights for resizing
    window.rowconfigure(0, minsize=500, weight=1)
    window.rowconfigure(1, minsize=50, weight=0)
    window.columnconfigure(0, minsize=500, weight=1)
    window.columnconfigure(1, minsize=200, weight=0)

    window.mainloop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chatroom server")
    parser.add_argument("-host", default="127.0.0.1", help="Interface the server is listening on")
    parser.add_argument("-p", metavar='PORT', type=int, default=1060, help='TCP port (default: 1060)')

    args = parser.parse_args()

    main(args.host, args.p)










