# -*- coding: utf-8 -*-
"""
Created on Wed Nov 13 15:47:41 2024

@author: Nanni Bassetti - nannibassetti.com
"""
import re
import dns.resolver
from email import message_from_string
from email.policy import default

def analizza_header_da_file(nome_file):
    with open(nome_file, "r") as file:
        header = file.read()
    msg = message_from_string(header, policy=default)
    # Estrai dominio dal campo From e verifica Reply-To
    dominio_mittente = estrai_dominio(header, "From")
    dominio_reply_to = estrai_dominio(header, "Reply-to")
    
    # Estrazione dominio mittente
    from_address = msg.get("From")
    #dominio = from_address.split('@')[-1] if from_address else ""
    
    # 1. Verifica del campo From e Reply-To
    reply_to = msg.get("Reply-to")
    if reply_to != from_address:
        print(f"Il campo Reply-To ({reply_to}) è diverso dal From ({from_address}).")
    else:
        print(f"Il campo Reply-To ({reply_to}) è uguale al From ({from_address}).")

    if dominio_mittente and dominio_reply_to:
        if dominio_mittente != dominio_reply_to:
            print("Anomalia: Il dominio di 'From' e 'Reply-To' non coincidono!")
        else:
            print("Mittente e Reply-To sono coerenti.")

    # Estrai selettore DKIM dall'header e verifica DKIM
    selettore_dkim = estrai_selettore_dkim(header)
    if selettore_dkim and dominio_mittente:
        verifica_dkim(selettore_dkim, dominio_mittente)
    else:
        print("Selettore DKIM non trovato o dominio mittente non disponibile.")

    # Verifica configurazioni SPF e DMARC per il dominio del mittente
    if dominio_mittente:
        verifica_spf(dominio_mittente)
        verifica_dmarc(dominio_mittente)
        verifica_catena_received(header,dominio_mittente)

    # Controllo anomalie nei server della catena Received
    

# Funzione per estrarre il dominio dal campo specificato dell'header
def estrai_dominio(header, campo):
    match = re.search(rf"{campo}:.*@([\w\.-]+)", header)
    if match:
        return match.group(1)
    return None

# Funzione per estrarre il selettore DKIM dal campo Authentication-Results
def estrai_selettore_dkim(header):
    match = re.search(r"Authentication-Results:.*dkim=.*?header.s=([\w-]+)", header, re.DOTALL)
    if match:
        return match.group(1)
    return None

# Funzione per verificare il record DKIM
def verifica_dkim(selettore, dominio):
    try:
        dkim_query = f"{selettore}._domainkey.{dominio}"
        answers = dns.resolver.resolve(dkim_query, 'TXT')
        dkim_presente = any("v=DKIM1" in str(rdata) for rdata in answers)
        if dkim_presente:
            print(f"DKIM configurato correttamente per {dominio} con selettore '{selettore}'.")
        else:
            print(f"DKIM non configurato correttamente per {dominio}.")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"DKIM non trovato per {dominio} con selettore '{selettore}'.")

# Funzione per verificare il record SPF
def verifica_spf(dominio):
    try:
        answers = dns.resolver.resolve(dominio, 'TXT')
        spf_presente = any("v=spf1" in str(rdata) for rdata in answers)
        if spf_presente:
            print(f"SPF configurato correttamente per {dominio}.")
        else:
            print(f"SPF non configurato per {dominio}.")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"SPF non trovato per {dominio}.")

# Funzione per verificare il record DMARC
def verifica_dmarc(dominio):
    try:
        dmarc_query = f"_dmarc.{dominio}"
        answers = dns.resolver.resolve(dmarc_query, 'TXT')
        dmarc_presente = any("v=DMARC1" in str(rdata) for rdata in answers)
        if dmarc_presente:
            print(f"DMARC configurato correttamente per {dominio}.")
        else:
            print(f"DMARC non configurato per {dominio}.")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        print(f"DMARC non trovato per {dominio}.")

# Funzione per verificare la catena dei server Received
def verifica_catena_received(header,dominio):
    received_servers = re.findall(r"Received: from ([\w\.-]+)", header)
    domini_autorizzati = [dominio]  # Esempio di domini legittimi

    # Analizza ciascun server nella catena `Received`
    for server in received_servers:
        if not any(server.endswith(dominio) for dominio in domini_autorizzati):
            print(f"Anomalia: Server non riconosciuto nella catena di Received: {server}")

# Esecuzione del programma
analizza_header_da_file("header.txt")

