# -*- coding: utf-8 -*-
"""
Created on Wed Nov 13 15:59:04 2024

@author: nannib
"""
import re
import dns.resolver
from email import message_from_string
from email.policy import default

def query_dns(domain, record_type):
    """
    Interroga il DNS per verificare la presenza di record DKIM, DMARC o SPF.
    """
    try:
        if record_type == "DMARC":
            query = f"_dmarc.{domain}"
        elif record_type == "SPF":
            query = domain
        elif record_type == "DKIM":
            # Si presume che il selettore sia "default"; in un caso reale, si richiederebbe il selettore corretto
            query = f"default._domainkey.{domain}"
        else:
            return None
        answers = dns.resolver.resolve(query, 'TXT')
        return [rdata.to_text() for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

def parse_email_header(header_text):
    """
    Analizza l'header di un'email e individua anomalie, incluse verifiche DNS per DKIM, DMARC e SPF.
    """
    
    msg = message_from_string(header_text, policy=default)
    anomalies = {}
    
    # Estrazione dominio mittente
    from_address = msg.get("From")
    domain = from_address.split('@')[-1] if from_address else ""

    # 1. Verifica del campo From e Reply-To
    reply_to = msg.get("Reply-To")
    if reply_to and reply_to != from_address:
        anomalies['Reply-To'] = f"Il campo Reply-To ({reply_to}) è diverso dal From ({from_address})."

    # 2. Verifica della presenza di DKIM, DMARC e SPF nei DNS del mittente
    dkim_record = query_dns(domain, "DKIM")
    if not dkim_record:
        anomalies['DKIM'] = f"Record DKIM mancante o non configurato correttamente per il dominio del mittente ({domain})."
    
    dmarc_record = query_dns(domain, "DMARC")
    if not dmarc_record:
        anomalies['DMARC'] = f"Record DMARC mancante o non configurato correttamente per il dominio del mittente ({domain})."
    
    spf_record = query_dns(domain, "SPF")
    if not spf_record or not any("v=spf1" in txt for txt in spf_record):
        anomalies['SPF'] = f"Record SPF mancante o non configurato correttamente per il dominio del mittente ({domain})."

    # 3. Verifica del campo Authentication-Results per i controlli del destinatario
    auth_results = msg.get("Authentication-Results")
    if auth_results:
        dkim_pass = "dkim=pass" in auth_results.lower()
        dmarc_pass = "dmarc=pass" in auth_results.lower()
        spf_pass = "spf=pass" in auth_results.lower()

        if dkim_pass and dmarc_pass and spf_pass:
            anomalies['Destinatario Check'] = "Il destinatario ha attivato e passato i controlli DKIM, DMARC e SPF."
        else:
            if "dkim=fail" in auth_results.lower() or "dkim=none" in auth_results.lower():
                anomalies['DKIM Check'] = "Il destinatario non ha validato DKIM o ha riscontrato un errore."
            if "dmarc=fail" in auth_results.lower():
                anomalies['DMARC Check'] = "Il destinatario non ha validato DMARC o ha riscontrato un errore."
            if "spf=fail" in auth_results.lower() or "spf=none" in auth_results.lower():
                anomalies['SPF Check'] = "Il destinatario non ha validato SPF o ha riscontrato un errore."
    else:
        anomalies['Authentication-Results'] = "Il destinatario non ha incluso i risultati di autenticazione (SPF/DKIM/DMARC)."

    # 4. Verifica del campo Received per server di inoltro sospetti
    received_fields = msg.get_all("Received")
    if received_fields:
        unusual_servers = []
        
        for received in received_fields:
            match = re.search(r'from\s+([\w.-]+)', received)
            if match:
                server = match.group(1)
                if domain not in server:  # Il server non appartiene al dominio del mittente
                    unusual_servers.append(server)
        
        if unusual_servers:
            anomalies['Received'] = f"Server non riconosciuti nella catena di Received: {', '.join(unusual_servers)}"

    return anomalies

# Lettura dell'header da file header.txt
with open("header.txt", "r") as file:
    header_text = file.read()

# Esecuzione dell'analisi e visualizzazione dei risultati
anomalies = parse_email_header(header_text)
if anomalies:
    print("Anomalie trovate nell'header:")
    for key, value in anomalies.items():
        print(f"- {key}: {value}")
else:
    print("Nessuna anomalia rilevata nell'header.")
