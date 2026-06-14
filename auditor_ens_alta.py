import socket
import ssl
import urllib.request
import urllib.error
import datetime
import json
import csv
import re
import time

# ---------------------------------------------------------
# Script per al TFG de Xavier Fluvia i Junyent
# Herramienta de soporte para auditoria tecnica ENS (Cat. ALTA)
# ---------------------------------------------------------

TARGET = "10.0.0.10"
PASSWORD = "Adminadmin12!"
PUERTOS_AUTORIZADOS = [80, 443]

# ---------------------------------------------------------
# FUNCIONES DE AYUDA
# ---------------------------------------------------------

def sacar_fecha():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")

def hacer_registro(verif, nivel, medida, dim, desc, evi, cat):
    diccionario = {
        "verificacion": verif,
        "nivel": nivel,
        "medida_ens": medida,
        "dimension": dim,
        "descripcion": desc,
        "evidencia": str(evi),
        "categoria": cat,
        "timestamp_utc": sacar_fecha()
    }
    return diccionario

def check_port(host, puerto):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        res = s.connect_ex((host, puerto))
        s.close()
        if res == 0:
            return True
        else:
            return False
    except:
        return False

def pedir_cabeceras(puerto, usar_https):
    if usar_https == True:
        url = "https://" + TARGET + ":" + str(puerto) + "/"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        url = "http://" + TARGET + ":" + str(puerto) + "/"
        ctx = None
        
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "auditor_ens_alta/4.0"})
        if ctx != None:
            resp = urllib.request.urlopen(req, timeout=3, context=ctx)
        else:
            resp = urllib.request.urlopen(req, timeout=3)
            
        cabeceras = dict(resp.headers)
        cabeceras["status"] = resp.status
        return cabeceras
    except urllib.error.HTTPError as e:
        cabeceras = dict(e.headers)
        cabeceras["status"] = e.code
        return cabeceras
    except Exception as e:
        return {"error": str(e)}

# ---------------------------------------------------------
# CAPA 1 - RED
# ---------------------------------------------------------

def v01_telnet():
    if check_port(TARGET, 23):
        return hacer_registro("V01", "FAIL", "mp.com.1", "C", "Puerto 23 Telnet activo", "puerto 23 abierto", "Directa")
    else:
        return hacer_registro("V01", "OK", "mp.com.1", "C", "Puerto 23 Telnet cerrado", "puerto 23 cerrado", "Directa")

def v02_ftp():
    if check_port(TARGET, 21):
        return hacer_registro("V02", "FAIL", "mp.com.1", "C", "Puerto 21 FTP activo", "puerto 21 abierto", "Directa")
    else:
        return hacer_registro("V02", "OK", "mp.com.1", "C", "Puerto 21 FTP cerrado", "puerto 21 cerrado", "Directa")

def v03_tftp():
    if check_port(TARGET, 69):
        return hacer_registro("V03", "FAIL", "mp.com.1", "C", "Puerto 69 TFTP activo", "puerto 69 abierto", "Directa")
    else:
        return hacer_registro("V03", "OK", "mp.com.1", "C", "Puerto 69 TFTP cerrado", "puerto 69 cerrado", "Directa")

def v04_ssh():
    if check_port(TARGET, 22):
        return hacer_registro("V04", "WARN", "op.exp.1", "C", "Puerto 22 SSH expuesto", "puerto 22 abierto", "Directa")
    else:
        return hacer_registro("V04", "OK", "op.exp.1", "C", "Puerto 22 SSH cerrado", "puerto 22 cerrado", "Directa")

def v05_rdp():
    if check_port(TARGET, 3389):
        return hacer_registro("V05", "WARN", "op.exp.1", "C", "Puerto 3389 RDP expuesto", "puerto 3389 abierto", "Directa")
    else:
        return hacer_registro("V05", "OK", "op.exp.1", "C", "Puerto 3389 RDP cerrado", "puerto 3389 cerrado", "Directa")

def v06_smb():
    if check_port(TARGET, 445):
        return hacer_registro("V06", "WARN", "op.exp.1", "C", "Puerto 445 SMB expuesto", "puerto 445 abierto", "Directa")
    else:
        return hacer_registro("V06", "OK", "op.exp.1", "C", "Puerto 445 SMB cerrado", "puerto 445 cerrado", "Directa")

def v07_puertos_autorizados():
    puertos = [21, 22, 23, 69, 80, 443, 445, 3389]
    abiertos = []
    
    for p in puertos:
        if check_port(TARGET, p):
            abiertos.append(p)
            
    malos = []
    for p in abiertos:
        if p not in PUERTOS_AUTORIZADOS:
            malos.append(p)
            
    if len(PUERTOS_AUTORIZADOS) == 0:
        return hacer_registro("V07", "WARN", "op.exp.1", "C", "No hay puertos autorizados configurados", str(abiertos), "Indirecta")
    elif len(malos) > 0:
        return hacer_registro("V07", "WARN", "op.exp.1", "C", "Hay puertos que no estan autorizados", str(malos), "Indirecta")
    else:
        return hacer_registro("V07", "OK", "op.exp.1", "C", "Puertos OK", str(abiertos), "Indirecta")

# ---------------------------------------------------------
# CAPA 2 - TRAZABILIDAD
# ---------------------------------------------------------

def v08_deriva_horaria():
    cabeceras = pedir_cabeceras(80, False)
    if "error" in cabeceras:
        cabeceras = pedir_cabeceras(443, True)
        
    if "Date" in cabeceras or "date" in cabeceras:
        try:
            from email.utils import parsedate_to_datetime
            if "Date" in cabeceras:
                fecha_server = parsedate_to_datetime(cabeceras["Date"])
            else:
                fecha_server = parsedate_to_datetime(cabeceras["date"])
                
            ahora = datetime.datetime.now(datetime.timezone.utc)
            diferencia = abs((ahora - fecha_server).total_seconds())
            
            if diferencia >= 60:
                return hacer_registro("V08", "FAIL", "op.mon.1", "T", "Deriva horaria muy grande", str(diferencia) + "s", "Directa")
            elif diferencia >= 5:
                return hacer_registro("V08", "WARN", "op.mon.1", "T", "Deriva horaria regular", str(diferencia) + "s", "Directa")
            else:
                return hacer_registro("V08", "OK", "op.mon.1", "T", "Deriva horaria bien", str(diferencia) + "s", "Directa")
        except:
            pass
            
    return hacer_registro("V08", "No evaluable", "op.mon.1", "T", "No puedo sacar la hora", "sin Date", "Directa")

def v09_logging_operativo():
    return hacer_registro("V09", "No evaluable", "op.log.1", "T", "No se puede mirar sin entrar al server", "-", "No evaluable")

# ---------------------------------------------------------
# CAPA 3A - WEB
# ---------------------------------------------------------

def v10_redireccion_http_https():
    try:
        import http.client
        conn = http.client.HTTPConnection(TARGET, 80, timeout=3)
        conn.request("GET", "/")
        resp = conn.getresponse()
        status = resp.status
        loc = resp.getheader("Location", "")
        conn.close()
        
        if (status == 301 or status == 302 or status == 308) and "https://" in loc:
            return hacer_registro("V10", "OK", "mp.sw.2", "C", "Redireccion funciona", loc, "Directa")
        else:
            return hacer_registro("V10", "FAIL", "mp.sw.2", "C", "No redirige bien", "status " + str(status), "Directa")
    except:
        return hacer_registro("V10", "No evaluable", "mp.sw.2", "C", "Puerto 80 caido", "-", "Directa")

def v11_hsts():
    cabs = pedir_cabeceras(443, True)
    if "error" in cabs:
        return hacer_registro("V11", "No evaluable", "mp.sw.2", "C", "Sin https", "-", "Directa")
        
    hsts = cabs.get("Strict-Transport-Security", cabs.get("strict-transport-security", ""))
    if hsts == "":
        return hacer_registro("V11", "FAIL", "mp.sw.2", "C", "Falta HSTS", "ausente", "Directa")
    
    if "max-age" in hsts:
        return hacer_registro("V11", "OK", "mp.sw.2", "C", "HSTS OK", hsts, "Directa")
    else:
        return hacer_registro("V11", "WARN", "mp.sw.2", "C", "HSTS raro", hsts, "Directa")

def v12_x_frame_options():
    cabs = pedir_cabeceras(443, True)
    if "error" in cabs:
        cabs = pedir_cabeceras(80, False)
        
    xfo = cabs.get("X-Frame-Options", cabs.get("x-frame-options", ""))
    if xfo != "":
        return hacer_registro("V12", "OK", "mp.sw.2", "I", "Tiene X-Frame", xfo, "Directa")
    else:
        return hacer_registro("V12", "FAIL", "mp.sw.2", "I", "No tiene X-Frame", "ausente", "Directa")

def v13_x_content_type_options():
    cabs = pedir_cabeceras(443, True)
    if "error" in cabs:
        cabs = pedir_cabeceras(80, False)
        
    xcto = cabs.get("X-Content-Type-Options", cabs.get("x-content-type-options", ""))
    if "nosniff" in xcto.lower():
        return hacer_registro("V13", "OK", "mp.sw.2", "I", "Tiene nosniff", xcto, "Directa")
    else:
        return hacer_registro("V13", "FAIL", "mp.sw.2", "I", "No tiene nosniff", "ausente", "Directa")

def v14_content_security_policy():
    cabs = pedir_cabeceras(443, True)
    if "error" in cabs:
        cabs = pedir_cabeceras(80, False)
        
    csp = cabs.get("Content-Security-Policy", cabs.get("content-security-policy", ""))
    if csp != "":
        return hacer_registro("V14", "OK", "mp.sw.2", "I", "Tiene CSP", csp, "Directa")
    else:
        return hacer_registro("V14", "FAIL", "mp.sw.2", "I", "Falta CSP", "ausente", "Directa")

def v15_cookies_seguras():
    cabs = pedir_cabeceras(443, True)
    if "error" in cabs:
        cabs = pedir_cabeceras(80, False)
        
    galletas = cabs.get("Set-Cookie", cabs.get("set-cookie", ""))
    if galletas == "":
        return hacer_registro("V15", "No evaluable", "mp.sw.2", "C", "No hay cookies", "-", "Directa")
        
    malas = []
    lista_galletas = galletas.split("\n")
    for galleta in lista_galletas:
        texto = galleta.lower()
        if "secure" not in texto or "httponly" not in texto:
            malas.append(galleta)
            
    if len(malas) > 0:
        return hacer_registro("V15", "FAIL", "mp.sw.2", "C", "Cookies sin seguro", str(malas), "Directa")
    else:
        return hacer_registro("V15", "OK", "mp.sw.2", "C", "Cookies OK", "perfecto", "Directa")

def v16_version_tls():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        ssock = ctx.wrap_socket(s, server_hostname=TARGET)
        ssock.connect((TARGET, 443))
        version = ssock.version()
        ssock.close()
        
        if version in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
            return hacer_registro("V16", "FAIL", "mp.sw.2", "A", "TLS viejo", version, "Indirecta")
        else:
            return hacer_registro("V16", "OK", "mp.sw.2", "A", "TLS bueno", version, "Indirecta")
    except Exception as e:
        return hacer_registro("V16", "No evaluable", "mp.sw.2", "A", "Fallo TLS", str(e), "Indirecta")

# ---------------------------------------------------------
# CAPA 3B - AUTENTICACION
# ---------------------------------------------------------

def v17_longitud_contrasena():
    if len(PASSWORD) >= 12:
        return hacer_registro("V17", "OK", "op.acc.1", "A", "Longitud buena", str(len(PASSWORD)), "Indirecta")
    else:
        return hacer_registro("V17", "FAIL", "op.acc.1", "A", "Longitud mala", str(len(PASSWORD)), "Indirecta")

def v18_complejidad_contrasena():
    mayus = False
    minus = False
    num = False
    for letra in PASSWORD:
        if letra.isupper(): mayus = True
        if letra.islower(): minus = True
        if letra.isdigit(): num = True
        
    if mayus and minus and num:
        return hacer_registro("V18", "OK", "op.acc.1", "A", "Tiene todo", "complejidad ok", "Indirecta")
    else:
        return hacer_registro("V18", "FAIL", "op.acc.1", "A", "Falta mayus, minus o numero", "-", "Indirecta")

def v19_simbolo_especial():
    raro = False
    for letra in PASSWORD:
        if not letra.isalnum():
            raro = True
            
    if raro:
        return hacer_registro("V19", "OK", "op.acc.1", "A", "Tiene simbolos", "ok", "Indirecta")
    else:
        return hacer_registro("V19", "FAIL", "op.acc.1", "A", "No tiene simbolos", "mal", "Indirecta")

def v20_credencial_trivial():
    basicas = ["admin", "admin123", "password", "123456", "qwerty", "admin123!", "root", "test"]
    if PASSWORD.lower() in basicas:
        return hacer_registro("V20", "FAIL", "op.acc.1", "A", "Contrasena muy facil", "trivial", "Indirecta")
    else:
        return hacer_registro("V20", "OK", "op.acc.1", "A", "Contrasena no es facil", "ok", "Indirecta")

# ---------------------------------------------------------
# CÓDIGO PRINCIPAL
# ---------------------------------------------------------

def main():
    print("=" * 72)
    print("  auditor_ens_alta v4.0  —  ENS Categoria ALTA (RD 311/2022)")
    print("=" * 72)
    print("  TARGET  : " + TARGET)
    print("  Inicio  : " + sacar_fecha())
    print("-" * 72)

    inicio_tiempo = datetime.datetime.now(datetime.timezone.utc)
    
    lista = [
        v01_telnet, v02_ftp, v03_tftp, v04_ssh, v05_rdp, v06_smb, v07_puertos_autorizados,
        v08_deriva_horaria, v09_logging_operativo, v10_redireccion_http_https,
        v11_hsts, v12_x_frame_options, v13_x_content_type_options, v14_content_security_policy,
        v15_cookies_seguras, v16_version_tls, v17_longitud_contrasena, v18_complejidad_contrasena,
        v19_simbolo_especial, v20_credencial_trivial
    ]
    
    nombres = [
        "V01_TELNET", "V02_FTP", "V03_TFTP", "V04_SSH", "V05_RDP", "V06_SMB", "V07_PUERTOS_AUTORIZADOS",
        "V08_DERIVA_HORARIA", "V09_LOGGING_OPERATIVO", "V10_REDIRECCION_HTTP_HTTPS",
        "V11_HSTS", "V12_X_FRAME_OPTIONS", "V13_X_CONTENT_TYPE_OPTIONS", "V14_CONTENT_SECURITY_POLICY",
        "V15_COOKIES_SEGURAS", "V16_VERSION_TLS", "V17_LONGITUD_CONTRASENA", "V18_COMPLEJIDAD_CONTRASENA",
        "V19_SIMBOLO_ESPECIAL", "V20_CREDENCIAL_TRIVIAL"
    ]

    resultados = []
    
    for i in range(len(lista)):
        num = i + 1
        if num < 10:
            num_str = "0" + str(num)
        else:
            num_str = str(num)
            
        print("  [" + num_str + "/20] " + nombres[i] + " ...", end=" ", flush=True)
        
        try:
            res = lista[i]()
        except Exception as e:
            res = hacer_registro(nombres[i][:3], "No evaluable", "-", "-", "Fallo general", str(e), "-")
            
        resultados.append(res)
        print(res["nivel"])

    fin_tiempo = datetime.datetime.now(datetime.timezone.utc)
    duracion = (fin_tiempo - inicio_tiempo).total_seconds()
    
    # Contar para el resumen
    resumen_dic = {"OK": 0, "WARN": 0, "FAIL": 0, "No evaluable": 0}
    for r in resultados:
        if "nivel" in r:
            niv = r["nivel"]
        else:
            niv = "No evaluable"
            
        if niv in resumen_dic:
            resumen_dic[niv] = resumen_dic[niv] + 1
        else:
            resumen_dic[niv] = 1

    ts = inicio_tiempo.strftime("%Y%m%dT%H%M%S")
    ruta_json = "auditoria_" + ts + ".json"
    ruta_csv  = "auditoria_" + ts + ".csv"

    # Guardar Json
    contexto = {
        "herramienta":  "auditor_ens_alta v4.0",
        "target":       TARGET,
        "inicio_utc":   inicio_tiempo.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "fin_utc":      fin_tiempo.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "duracion_s":   round(duracion, 2),
        "total_checks": len(resultados),
        "resumen":      resumen_dic
    }
    
    dic_final = {"contexto": contexto, "resultados": resultados}
    with open(ruta_json, "w", encoding="utf-8") as f:
        json.dump(dic_final, f, ensure_ascii=False, indent=2)

    # Guardar CSV (basico)
    cabeceras_csv = ["verificacion", "nivel", "medida_ens", "dimension", "descripcion", "evidencia", "categoria", "timestamp_utc"]
    with open(ruta_csv, "w", newline="", encoding="utf-8") as f:
        escritor = csv.writer(f)
        escritor.writerow(cabeceras_csv)
        for r in resultados:
            # Pasar dict/list de evidencia a string para que no explote
            evi = r["evidencia"]
            if type(evi) is dict or type(evi) is list:
                evi = json.dumps(evi, ensure_ascii=False)
                
            fila = [
                r.get("verificacion", ""),
                r.get("nivel", ""),
                r.get("medida_ens", ""),
                r.get("dimension", ""),
                r.get("descripcion", ""),
                evi,
                r.get("categoria", ""),
                r.get("timestamp_utc", "")
            ]
            escritor.writerow(fila)

    print("-" * 72)
    print("  RESUMEN  OK:" + str(resumen_dic["OK"]) + "  WARN:" + str(resumen_dic["WARN"]) + "  FAIL:" + str(resumen_dic["FAIL"]) + "  No evaluable:" + str(resumen_dic["No evaluable"]))
    print("  Duracion : " + str(round(duracion, 1)) + "s")
    print("  JSON     : " + ruta_json)
    print("  CSV      : " + ruta_csv)
    print("=" * 72)

if __name__ == "__main__":
    main()
print("\nFin de la auditoría.\n")
