import PySimpleGUI as sg
import hashlib
import sqlite3
from sqlite3 import Error
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
#database
connection = sqlite3.connect('password.db')
c = connection.cursor()
#passwordmanager login and GUI
def main():
    #MainWindowGUI
    def passwordgeneratorGUI():
        # get encryption out
        sql_select_query = """select * from encryptiontest"""
        c.execute(sql_select_query)
        records = c.fetchall()
        for row in records:
            encryptionkey = row[1]
        #decrypt data
        encryptionkeyencode = encryptionkey.encode()

        #layout
        layout = [
            [sg.Text('app/website name:'), sg.InputText('', size=(26, 1),), sg.Button('search')],
            [sg.Text('username:'), sg.MLine(key='-ML1-' + sg.WRITE_ONLY_KEY, size=(26, 1))],
            [sg.Text('password:'), sg.MLine(key='-ML2-' + sg.WRITE_ONLY_KEY, size=(26, 1))],
            [sg.Button('add',size=(5, 1)),sg.Button('delete', size=(5, 1)), sg.Button('exit', size=(5, 1))],
        ]
        window = sg.Window('passwordmanager', layout,
                           auto_size_text=False,
                           default_element_size=(14, 1),
                           text_justification='r',
                           return_keyboard_events=True,
                           grab_anywhere=False,
                           finalize=True)
        while True:
            event, values = window.read()
            if event == 'delete':
                deletesite = sg.popup_get_text('delete your account for this site:')
                c.execute("DELETE from passwordDB WHERE site=?", (deletesite,))
                connection.commit
            if event == 'add':
                newsite = sg.popup_get_text('new site:', size=(30,2))
                newusername = sg.popup_get_text('new username:', size=(30,2)).encode()
                newpassword = sg.popup_get_text('new password:', size=(30,2)).encode()
                f = Fernet(encryptionkeyencode)
                encryptnewusername = f.encrypt(newusername).decode()
                encyptnewpassword = f.encrypt(newpassword).decode()
                c.execute("INSERT INTO passwordDB (site, username, password) VALUES (?, ?, ?)", (newsite, encryptnewusername, encyptnewpassword))
                connection.commit
            if event == sg.WIN_CLOSED or event == 'exit':
                delete = """DELETE from encryptiontest where id = 1"""
                c.execute(delete)
                connection.commit()
                c.close()
                connection.close()
                break
            if event == 'search':
                window['-ML1-' + sg.WRITE_ONLY_KEY].update('')
                window['-ML2-' + sg.WRITE_ONLY_KEY].update('')
                sitename = values[0]
                c.execute("SELECT * from passwordDB WHERE site=?", (sitename,))
                records1 = c.fetchall()
                for row in records1:
                    encrypteduserdata = str(row[1])
                    encryptedpassdata = str(row[2])
                    if encrypteduserdata == '':
                        continue
                    else:
                        encrypteduserdataencode = encrypteduserdata.encode()
                        encryptedpassdataencode = encryptedpassdata.encode()
                        key = encryptionkey
                        f = Fernet(key)
                        decrypted_username = f.decrypt(encrypteduserdataencode).decode()
                        decrypted_password = f.decrypt(encryptedpassdataencode).decode()
                        window['-ML1-' + sg.WRITE_ONLY_KEY].print(decrypted_username, end='')
                        window['-ML2-' + sg.WRITE_ONLY_KEY].print(decrypted_password, end='')
        window.close()
    #safelogin
    while True:
        # loginGUI
        password = sg.popup_get_text('Password: ', 'passwordmanager', password_char='*', size=(15,2))
        hash = b'\x05u0\xf7\xbc\xe17\xc8\x15\xc8V\xbc\x9d\xb7>\x9e\xa2\xe7%\xa7\xbf\x88bq\xafOu\xc6\x91\x8d*\x1d\xc3O\xeb\xab\xa7\xef\xef\xdd\x14\x8f\x02X\xf0\xd6\xb1\xf2\xa3\x0fE\xfd\xf9\xb7\xd7\xb2\x0e\xca\xb68*\x08\x92\x0b'
        salt = b'\x05u0\xf7\xbc\xe17\xc8\x15\xc8V\xbc\x9d\xb7>\x9e\xa2\xe7%\xa7\xbf\x88bq\xafOu\xc6\x91\x8d*\x1d'
        passwordinput = password
        key1 = hashlib.pbkdf2_hmac('sha256', passwordinput.encode('utf-8'), salt, 100000)
        attemptpassword = salt + key1
        # encryptionkey make
        mysalt = b'\xa9\xc4e\x1e\xecO\x809j\xb0\x17Y\xe40\xc1\x82'
        password1 = password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256,
            length=32,
            salt=mysalt,
            iterations=100000,
            backend=default_backend()
        )
        key2 = base64.urlsafe_b64encode(kdf.derive(password1))
        keydecode = key2.decode()

        if attemptpassword == hash:
            id = (1)
            c.execute("INSERT INTO encryptiontest (id, encrytpionkey) VALUES (?, ?)",(id, keydecode))
            connection.commit()
            passwordgeneratorGUI()
            return

        else:
            sg.popup('Wrong Password')

if __name__ == '__main__':
    sg.theme('DarkGrey11')
main()