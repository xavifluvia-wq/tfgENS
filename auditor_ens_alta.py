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
# CONFIGURACIÓN (Como en el script básico)
# ---------------------------------------------------------
TARGET = input("Introduce IP o dominio a auditar (ej: 10.0.0.10): ")
if TARGET == "":
    TARGET = "10.0.0.10"

PASSWORD = input("Introduce contrasena a evaluar (ej: Adminadmin12!): ")
if PASSWORD == "":
    PASSWORD = "Adminadmin12!"

PUERTOS_AUTORIZADOS = [80, 443]

# ---------------------------------------------------------
# FUNCIONES DE AYUDA
# ---------------------------------------------------------
def sacar_fecha():
    # Saca la fecha en formato UTC
    ahora = datetime.datetime.utcnow()
    return ahora.strftime("%Y-%m-%dT%H:%M:%S+00:00")

def hacer_registro(verif, nivel, medida, dim, desc, evi, cat):
    # Crea el diccionario igual que el profesional
    diccionario = {}
    diccionario["verificacion"] = verif
    diccionario["nivel"] = nivel
    diccionario["medida_ens"] = medida
    diccionario["dimension"] = dim
    diccionario["descripcion"] = desc
    diccionario["evidencia"] = evi # Lo dejamos como variable (puede ser dict)
    diccionario["categoria"] = cat
    diccionario["timestamp_utc"] = sacar_fecha()
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
    # Hace una peticion HTTP basica
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
        cabeceras["_status"] = resp.status
        return cabeceras
    except urllib.error.HTTPError as e:
        cabeceras = dict(e.headers)
        cabeceras["_status"] = e.code
        cabeceras["_error"] = str(e)
        return cabeceras
    except Exception as e:
        cabeceras = {}
        cabeceras["_error"] = str(e)
        return cabeceras

# ---------------------------------------------------------
# CAPA 1 - RED
# ---------------------------------------------------------
def v01_telnet():
    if check_port(TARGET, 23):
        return hacer_registro("V01", "FAIL", "mp.com.1", "C", "Puerto 23 Telnet activo — protocolo en texto claro prohibido en Cat. ALTA", "puerto 23 abierto", "Directa")
    else:
        return hacer_registro("V01", "OK", "mp.com.1", "C", "Puerto 23 Telnet cerrado", "puerto 23 cerrado", "Directa")

def v02_ftp():
    if check_port(TARGET, 21):
        return hacer_registro("V02", "FAIL", "mp.com.1", "C", "Puerto 21 FTP activo — transferencia en texto claro prohibida en Cat. ALTA", "puerto 21 abierto", "Directa")
    else:
        return hacer_registro("V02", "OK", "mp.com.1", "C", "Puerto 21 FTP cerrado", "puerto 21 cerrado", "Directa")

def v03_tftp():
    if check_port(TARGET, 69):
        return hacer_registro("V03", "FAIL", "mp.com.1", "C", "Puerto 69 TFTP activo — protocolo sin autenticacion ni cifrado", "puerto 69 abierto", "Directa")
    else:
        return hacer_registro("V03", "OK", "mp.com.1", "C", "Puerto 69 TFTP cerrado", "puerto 69 cerrado", "Directa")

def v04_ssh():
    if check_port(TARGET, 22):
        return hacer_registro("V04", "WARN", "op.exp.1", "C", "Puerto 22 SSH expuesto — verificar restriccion de acceso (ACL, VPN, MFA)", "puerto 22 accesible desde la red de auditoria", "Directa")
    else:
        return hacer_registro("V04", "OK", "op.exp.1", "C", "Puerto 22 SSH no accesible desde la red de auditoria", "puerto 22 cerrado o filtrado", "Directa")

def v05_rdp():
    if check_port(TARGET, 3389):
        return hacer_registro("V05", "WARN", "op.exp.1", "C", "Puerto 3389 RDP expuesto — requiere justificacion, MFA y controles adicionales en Cat. ALTA", "puerto 3389 accesible", "Directa")
    else:
        return hacer_registro("V05", "OK", "op.exp.1", "C", "Puerto 3389 RDP no accesible", "puerto 3389 cerrado", "Directa")

def v06_smb():
    if check_port(TARGET, 445):
        return hacer_registro("V06", "WARN", "op.exp.1", "C", "Puerto 445 SMB expuesto — vector de alto riesgo (EternalBlue, WannaCry); requiere aislamiento", "puerto 445 accesible", "Directa")
    else:
        return hacer_registro("V06", "OK", "op.exp.1", "C", "Puerto 445 SMB no accesible", "puerto 445 cerrado", "Directa")

def v07_puertos_autorizados():
    puertos_a_verificar = [21, 22, 23, 69, 80, 443, 445, 3389]
    abiertos = []
    
    for p in puertos_a_verificar:
        if check_port(TARGET, p):
            abiertos.append(p)
            
    no_autorizados = []
    for p in abiertos:
        if p not in PUERTOS_AUTORIZADOS:
            no_autorizados.append(p)
            
    if len(PUERTOS_AUTORIZADOS) == 0:
        evidencia_dict = {"abiertos": abiertos, "autorizados": PUERTOS_AUTORIZADOS}
        return hacer_registro("V07", "WARN", "op.exp.1", "C", "Lista de puertos autorizados no definida — no es posible verificar el inventario", evidencia_dict, "Indirecta")
    elif len(no_autorizados) > 0:
        evidencia_dict = {"abiertos": abiertos, "no_autorizados": no_autorizados, "autorizados": PUERTOS_AUTORIZADOS}
        return hacer_registro("V07", "WARN", "op.exp.1", "C", "Puertos abiertos no incluidos en la lista de servicios autorizados", evidencia_dict, "Indirecta")
    else:
        evidencia_dict = {"abiertos": abiertos, "autorizados": PUERTOS_AUTORIZADOS}
        return hacer_registro("V07", "OK", "op.exp.1", "C", "Todos los puertos abiertos figuran en la lista de servicios autorizados", evidencia_dict, "Indirecta")

# ---------------------------------------------------------
# CAPA 2 - TRAZABILIDAD
# ---------------------------------------------------------
def v08_deriva_horaria():
    from email.utils import parsedate_to_datetime
    
    cabeceras = pedir_cabeceras(80, False)
    if "_error" in cabeceras:
        cabeceras = pedir_cabeceras(443, True)
        
    date_val = ""
    if "Date" in cabeceras:
        date_val = cabeceras["Date"]
    elif "date" in cabeceras:
        date_val = cabeceras["date"]
        
    if date_val != "":
        try:
            srv_time = parsedate_to_datetime(date_val)
            now = datetime.datetime.now(datetime.timezone.utc)
            deriva = abs((now - srv_time).total_seconds())
            
            evidencia_texto = str(int(deriva)) + " s"
            
            if deriva >= 60:
                return hacer_registro("V08", "FAIL", "op.mon.1", "T", "Deriva horaria elevada — correlacion de eventos comprometida", evidencia_texto, "Directa")
            elif deriva >= 5:
                return hacer_registro("V08", "WARN", "op.mon.1", "T", "Deriva horaria moderada — posible problema de sincronizacion NTP", evidencia_texto, "Directa")
            else:
                return hacer_registro("V08", "OK", "op.mon.1", "T", "Sincronizacion temporal correcta — deriva dentro del umbral", evidencia_texto, "Directa")
        except:
            pass
            
    return hacer_registro("V08", "No evaluable", "op.mon.1", "T", "No se puede obtener referencia temporal del objetivo", "sin respuesta HTTP/S con cabecera Date", "Directa")

def v09_logging_operativo():
    return hacer_registro("V09", "No evaluable", "op.log.1", "T", "Logging: requiere acceso al sistema o SIEM — no evaluable en modalidad observacional", "no evaluable sin acceso directo al sistema auditado", "No evaluable")

# ---------------------------------------------------------
# CAPA 3A - WEB
# ---------------------------------------------------------
def v10_redireccion_http_https():
    try:
        import http.client
        conn = http.client.HTTPConnection(TARGET, 80, timeout=3)
        conn.request("GET", "/", headers={"User-Agent": "auditor_ens_alta/4.0"})
        resp = conn.getresponse()
        status = resp.status
        location = resp.getheader("Location", "")
        conn.close()
        
        if (status == 301 or status == 302 or status == 303 or status == 307 or status == 308) and location.startswith("https://"):
            return hacer_registro("V10", "OK", "mp.sw.2", "C", "Redireccion HTTP -> HTTPS correcta (" + str(status) + ")", location, "Directa")
        else:
            if location == "":
                location = "ausente"
            return hacer_registro("V10", "FAIL", "mp.sw.2", "C", "No se detecta redireccion HTTP -> HTTPS", "status=" + str(status) + " location=" + location, "Directa")
    except Exception as exc:
        return hacer_registro("V10", "No evaluable", "mp.sw.2", "C", "Puerto 80 no accesible — no se puede verificar la redireccion", str(exc), "Directa")

def v11_hsts():
    cab = pedir_cabeceras(443, True)
    if "_error" in cab and "_status" not in cab:
        return hacer_registro("V11", "No evaluable", "mp.sw.2", "C", "No se puede conectar por HTTPS para verificar HSTS", cab["_error"], "Directa")
        
    hsts = ""
    if "Strict-Transport-Security" in cab:
        hsts = cab["Strict-Transport-Security"]
    elif "strict-transport-security" in cab:
        hsts = cab["strict-transport-security"]
        
    if hsts == "":
        return hacer_registro("V11", "FAIL", "mp.sw.2", "C", "Cabecera HSTS ausente", "no presente", "Directa")
    
    if "max-age" in hsts:
        numero = 0
        import re
        m = re.search(r"max-age=(\d+)", hsts)
        if m:
            numero = int(m.group(1))
            
        if numero >= 31536000:
            return hacer_registro("V11", "OK", "mp.sw.2", "C", "Cabecera HSTS presente con max-age suficiente (>= 1 anno)", hsts, "Directa")
        else:
            return hacer_registro("V11", "WARN", "mp.sw.2", "C", "Cabecera HSTS presente pero max-age insuficiente (< 1 anno)", hsts, "Directa")
    return hacer_registro("V11", "WARN", "mp.sw.2", "C", "Cabecera HSTS presente pero max-age insuficiente (< 1 anno)", hsts, "Directa")

def v12_x_frame_options():
    cab = pedir_cabeceras(443, True)
    if "_error" in cab and "_status" not in cab:
        cab = pedir_cabeceras(80, False)
        
    xfo = ""
    if "X-Frame-Options" in cab:
        xfo = cab["X-Frame-Options"]
    elif "x-frame-options" in cab:
        xfo = cab["x-frame-options"]
        
    if xfo != "":
        return hacer_registro("V12", "OK", "mp.sw.2", "I", "Cabecera X-Frame-Options presente", xfo, "Directa")
    else:
        return hacer_registro("V12", "FAIL", "mp.sw.2", "I", "Cabecera X-Frame-Options ausente — riesgo de clickjacking", "no presente", "Directa")

def v13_x_content_type_options():
    cab = pedir_cabeceras(443, True)
    if "_error" in cab and "_status" not in cab:
        cab = pedir_cabeceras(80, False)
        
    xcto = ""
    if "X-Content-Type-Options" in cab:
        xcto = cab["X-Content-Type-Options"]
    elif "x-content-type-options" in cab:
        xcto = cab["x-content-type-options"]
        
    if xcto != "":
        if "nosniff" in xcto.lower():
            return hacer_registro("V13", "OK", "mp.sw.2", "I", "Cabecera X-Content-Type-Options: nosniff presente", xcto, "Directa")
        else:
            return hacer_registro("V13", "WARN", "mp.sw.2", "I", "Cabecera X-Content-Type-Options presente con valor inesperado", xcto, "Directa")
    else:
        return hacer_registro("V13", "FAIL", "mp.sw.2", "I", "Cabecera X-Content-Type-Options ausente", "no presente", "Directa")

def v14_content_security_policy():
    cab = pedir_cabeceras(443, True)
    if "_error" in cab and "_status" not in cab:
        cab = pedir_cabeceras(80, False)
        
    csp = ""
    if "Content-Security-Policy" in cab:
        csp = cab["Content-Security-Policy"]
    elif "content-security-policy" in cab:
        csp = cab["content-security-policy"]
        
    if csp != "":
        return hacer_registro("V14", "OK", "mp.sw.2", "I", "Cabecera Content-Security-Policy presente", csp[:300], "Directa")
    else:
        return hacer_registro("V14", "FAIL", "mp.sw.2", "I", "Cabecera Content-Security-Policy ausente", "no presente", "Directa")

def v15_cookies_seguras():
    cab = pedir_cabeceras(443, True)
    if "_error" in cab and "_status" not in cab:
        cab = pedir_cabeceras(80, False)
        
    set_cookie = ""
    if "Set-Cookie" in cab:
        set_cookie = cab["Set-Cookie"]
    elif "set-cookie" in cab:
        set_cookie = cab["set-cookie"]
        
    if set_cookie == "":
        return hacer_registro("V15", "No evaluable", "mp.sw.2", "C", "El servicio no emite ninguna cookie — no evaluable", "sin cabecera Set-Cookie", "Directa")
        
    cookies = []
    lista_temp = set_cookie.split("\n")
    for c in lista_temp:
        if c.strip() != "":
            cookies.append(c.strip())
            
    if len(cookies) == 0:
        cookies.append(set_cookie)
        
    deficientes = []
    for cookie in cookies:
        cookie_lower = cookie.lower()
        nombre = cookie.split("=")[0].strip()
        sin_secure = False
        sin_httponly = False
        
        if "secure" not in cookie_lower:
            sin_secure = True
        if "httponly" not in cookie_lower:
            sin_httponly = True
            
        if sin_secure == True or sin_httponly == True:
            dict_error = {}
            dict_error["cookie"] = nombre
            dict_error["sin_secure"] = sin_secure
            dict_error["sin_httponly"] = sin_httponly
            deficientes.append(dict_error)
            
    if len(deficientes) > 0:
        return hacer_registro("V15", "FAIL", "mp.sw.2", "C", "Alguna cookie carece de atributo Secure o HttpOnly", deficientes, "Directa")
    else:
        return hacer_registro("V15", "OK", "mp.sw.2", "C", "Todas las cookies incluyen los atributos Secure y HttpOnly", str(len(cookies)) + " cookie(s) verificada(s)", "Directa")

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
        
        protocolos_obsoletos = ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]
        if version in protocolos_obsoletos:
            return hacer_registro("V16", "FAIL", "mp.sw.2", "A", "Version TLS obsoleta negociada: " + version, version, "Indirecta")
        else:
            return hacer_registro("V16", "OK", "mp.sw.2", "A", "Version TLS aceptable negociada: " + version, version, "Indirecta")
    except Exception as e:
        return hacer_registro("V16", "No evaluable", "mp.sw.2", "A", "No se puede establecer conexion TLS con el objetivo", str(e), "Indirecta")

# ---------------------------------------------------------
# CAPA 3B - AUTENTICACION
# ---------------------------------------------------------
def v17_longitud_contrasena():
    longitud = len(PASSWORD)
    if longitud >= 12:
        return hacer_registro("V17", "OK", "op.acc.1", "A", "Longitud de contrasena suficiente (" + str(longitud) + " caracteres)", str(longitud) + " caracteres", "Indirecta")
    else:
        return hacer_registro("V17", "FAIL", "op.acc.1", "A", "Longitud de contrasena insuficiente (" + str(longitud) + " < 12 caracteres)", str(longitud) + " caracteres", "Indirecta")

def v18_complejidad_contrasena():
    tiene_may = False
    tiene_min = False
    tiene_dig = False
    
    for letra in PASSWORD:
        if letra.isupper(): tiene_may = True
        if letra.islower(): tiene_min = True
        if letra.isdigit(): tiene_dig = True
        
    detalle = {}
    detalle["mayusculas"] = tiene_may
    detalle["minusculas"] = tiene_min
    detalle["digitos"] = tiene_dig
    
    if tiene_may and tiene_min and tiene_dig:
        return hacer_registro("V18", "OK", "op.acc.1", "A", "Contrasena contiene mayusculas, minusculas y digitos", detalle, "Indirecta")
    else:
        return hacer_registro("V18", "FAIL", "op.acc.1", "A", "Contrasena carece de mayusculas, minusculas o digitos", detalle, "Indirecta")

def v19_simbolo_especial():
    tiene_especial = False
    for letra in PASSWORD:
        if not letra.isalnum():
            tiene_especial = True
            
    if tiene_especial:
        return hacer_registro("V19", "OK", "op.acc.1", "A", "Contrasena contiene al menos un simbolo especial", "simbolo especial presente", "Indirecta")
    else:
        return hacer_registro("V19", "FAIL", "op.acc.1", "A", "Contrasena sin simbolos especiales — solo caracteres alfanumericos", "sin simbolo especial", "Indirecta")

def v20_credencial_trivial():
    triviales = ["admin", "admin123", "password", "123456", "qwerty", "admin123!", "password1", "123456789", "12345678", "12345", "1234567890", "letmein", "welcome", "monkey", "dragon", "master", "login", "root", "toor", "test", "guest", "changeme"]
    pwd_lower = PASSWORD.lower()
    
    if pwd_lower in triviales:
        return hacer_registro("V20", "FAIL", "op.acc.1", "A", "Contrasena representativa figura en la lista de credenciales triviales", "coincidencia en lista de triviales", "Indirecta")
    else:
        return hacer_registro("V20", "OK", "op.acc.1", "A", "Contrasena no encontrada en la lista de credenciales triviales", "sin coincidencia", "Indirecta")

# ---------------------------------------------------------
# CÓDIGO PRINCIPAL
# ---------------------------------------------------------
def main():
    inicio_tiempo = datetime.datetime.now(datetime.timezone.utc)
    
    print("=" * 72)
    print("  auditor_ens_alta v4.0  —  ENS Categoria ALTA (RD 311/2022)")
    print("=" * 72)
    print("  TARGET  : " + TARGET)
    print("  Inicio  : " + inicio_tiempo.strftime("%Y-%m-%dT%H:%M:%S+00:00"))
    print("-" * 72)

    # Funciones manuales guardadas en una lista
    lista_verificaciones = [
        v01_telnet, v02_ftp, v03_tftp, v04_ssh, v05_rdp, v06_smb, v07_puertos_autorizados,
        v08_deriva_horaria, v09_logging_operativo, v10_redireccion_http_https,
        v11_hsts, v12_x_frame_options, v13_x_content_type_options, v14_content_security_policy,
        v15_cookies_seguras, v16_version_tls, v17_longitud_contrasena, v18_complejidad_contrasena,
        v19_simbolo_especial, v20_credencial_trivial
    ]
    
    nombres_verificaciones = [
        "v01_telnet", "v02_ftp", "v03_tftp", "v04_ssh", "v05_rdp", "v06_smb", "v07_puertos_autorizados",
        "v08_deriva_horaria", "v09_logging_operativo", "v10_redireccion_http_https",
        "v11_hsts", "v12_x_frame_options", "v13_x_content_type_options", "v14_content_security_policy",
        "v15_cookies_seguras", "v16_version_tls", "v17_longitud_contrasena", "v18_complejidad_contrasena",
        "v19_simbolo_especial", "v20_credencial_trivial"
    ]

    resultados = []
    
    for i in range(len(lista_verificaciones)):
        num = i + 1
        num_str = str(num)
        if num < 10:
            num_str = "0" + num_str
            
        nombre = nombres_verificaciones[i].upper()
        print("  [" + num_str + "/20] " + nombre + " ...", end=" ", flush=True)
        
        try:
            res = lista_verificaciones[i]()
        except Exception as e:
            res = hacer_registro(nombre[:3], "No evaluable", "-", "-", "Error inesperado en " + nombre.lower(), str(e), "-")
            
        resultados.append(res)
        print(res["nivel"])

    fin_tiempo = datetime.datetime.now(datetime.timezone.utc)
    duracion = (fin_tiempo - inicio_tiempo).total_seconds()
    
    # Contar resultados
    resumen_dic = {"OK": 0, "WARN": 0, "FAIL": 0, "No evaluable": 0}
    for r in resultados:
        niv = ""
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

    # Guardar Json igual que el original
    contexto = {}
    contexto["herramienta"] = "auditor_ens_alta v4.0"
    contexto["target"] = TARGET
    contexto["inicio_utc"] = inicio_tiempo.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    contexto["fin_utc"] = fin_tiempo.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    contexto["duracion_s"] = round(duracion, 2)
    contexto["total_checks"] = len(resultados)
    contexto["resumen"] = resumen_dic
    
    dic_final = {}
    dic_final["contexto"] = contexto
    dic_final["resultados"] = resultados
    
    f = open(ruta_json, "w", encoding="utf-8")
    json.dump(dic_final, f, ensure_ascii=False, indent=2)
    f.close()

    # Guardar CSV exactamente con las mismas columnas
    cabeceras_csv = ["verificacion", "nivel", "medida_ens", "dimension", "descripcion", "evidencia", "categoria", "timestamp_utc"]
    f_csv = open(ruta_csv, "w", newline="", encoding="utf-8")
    escritor = csv.writer(f_csv)
    escritor.writerow(cabeceras_csv)
    
    for r in resultados:
        evi = r["evidencia"]
        # Convertir diccionarios a string de json para que el CSV no pete
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
    f_csv.close()

    print("-" * 72)
    print("  RESUMEN  OK:" + str(resumen_dic["OK"]) + "  WARN:" + str(resumen_dic["WARN"]) + "  FAIL:" + str(resumen_dic["FAIL"]) + "  No evaluable:" + str(resumen_dic["No evaluable"]))
    duracion_redondeada = round(duracion, 1)
    print("  Duracion : " + str(duracion_redondeada) + "s")
    print("  JSON     : " + ruta_json)
    print("  CSV      : " + ruta_csv)
    print("=" * 72)

if __name__ == "__main__":
    main()
