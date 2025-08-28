Evo kompletan `README.md` koji možeš samo da kopiraš u fajl:

````markdown
# SecureTalk – Sigurna Messaging i VoIP Aplikacija

SecureTalk je aplikacija za razmenu poruka i fajlova preko mreže, razvijena u Python-u. Aplikacija koristi **end-to-end enkripciju**, digitalno potpisivanje poruka i bezbednu razmenu ključeva kako bi obezbedila privatnu komunikaciju između korisnika.  
Sastoji se iz **server** i **klijent** dela:  
- Server služi za registraciju korisnika, kreiranje soba i prosleđivanje poruka/fajlova.  
- Klijent ima grafički interfejs za slanje i primanje poruka u realnom vremenu.  

---

## Funkcionalnosti
- ✅ Registracija korisnika i soba  
- ✅ Razmena javnih kriptografskih ključeva (Diffie-Hellman)  
- ✅ Digitalno potpisivanje poruka (RSA)  
- ✅ End-to-end enkripcija (AES-GCM)  
- ✅ Sigurno slanje fajlova (podela u blokove, enkripcija svakog bloka)  
- ✅ Notifikacije kada korisnici uđu ili izađu iz sobe  
- ✅ Jednostavan GUI klijent zasnovan na `tkinter` biblioteci  

---

## Tehnologije
- **Python 3.10+**
- **FastAPI** za serverski deo  
- **WebSocket** za real-time komunikaciju  
- **cryptography** za RSA, AES i Diffie-Hellman enkripciju  
- **tkinter** za GUI klijenta  

---

## Instalacija i Pokretanje

### 1. Kloniranje repozitorijuma
```bash
git clone https://github.com/korisnik/securetalk.git
cd securetalk
````

### 2. Kreiranje virtuelnog okruženja i instalacija zavisnosti

```bash
python -m venv venv
source venv/bin/activate   # Linux / macOS
venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

### 3. Pokretanje servera

```bash
uvicorn server:app --host 0.0.0.0 --port 8000
```

Server se sada pokreće na `http://localhost:8000`.

### 4. Pokretanje klijenta

```bash
python client.py
```

---

## Korišćenje

1. Pokrenite server pomoću komande iznad.
2. Pokrenite klijentsku aplikaciju.
3. Unesite svoje korisničko ime i sobu (ili pritisnite enter za podrazumevanu "lobby" sobu).
4. Počnite da šaljete poruke i fajlove drugim korisnicima u sobi.
5. Poruke i fajlovi se automatski enkriptuju i potpisuju.

---

## Struktura Projekta

```
securetalk/
│
├── server.py        # Serverska aplikacija (FastAPI + WebSocket)
├── client.py        # Klijentska aplikacija (tkinter GUI)
├── crypto_utils.py  # Funkcije za generisanje i upravljanje ključevima
├── requirements.txt # Lista Python zavisnosti
└── README.md        # Uputstvo za instalaciju i korišćenje
```

---

## Literatura

* Python FastAPI dokumentacija: [https://fastapi.tiangolo.com/](https://fastapi.tiangolo.com/)
* Python WebSocket dokumentacija: [https://websockets.readthedocs.io/](https://websockets.readthedocs.io/)
* Python cryptography paket: [https://cryptography.io/en/latest/](https://cryptography.io/en/latest/)
* Tkinter dokumentacija: [https://docs.python.org/3/library/tkinter.html](https://docs.python.org/3/library/tkinter.html)
* Uvod u enkripciju: [https://www.cryptopals.com/](https://www.cryptopals.com/)
* Diffie–Hellman Key Exchange: [https://en.wikipedia.org/wiki/Diffie–Hellman\_key\_exchange](https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange)
* RSA algoritam: [https://en.wikipedia.org/wiki/RSA\_(cryptosystem)](https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29)

---

## Autori

Seminarski rad iz predmeta **Projektovanje i implementacija bezbednosnog softvera**
Autor: *Milan Jovanović*
