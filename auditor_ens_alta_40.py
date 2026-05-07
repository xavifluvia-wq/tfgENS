import socket

# -----------------------------------------
# CONFIGURACIÓN
# -----------------------------------------
TARGET = input("Introduce IP o dominio a auditar: ")

# Puertos básicos a comprobar (servicios inseguros)
PORTS = {
    21: "FTP",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    22: "SSH"
}

# -----------------------------------------
# FUNCIÓN DE ESCANEO
# -----------------------------------------
def check_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((host, port))
    s.close()
    return result == 0


# -----------------------------------------
# AUDITORÍA BÁSICA
# -----------------------------------------
print("\nIniciando auditoría básica...\n")

results = []

for port, service in PORTS.items():
    is_open = check_port(TARGET, port)

    if is_open:
        if port in [21, 23]:
            status = "FAIL"
        elif port == 80:
            status = "WARN"
        else:
            status = "OK"
        print(f"[{status}] Puerto {port} ({service}) ABIERTO")
    else:
        status = "OK"
        print(f"[OK] Puerto {port} ({service}) cerrado")

    results.append((port, service, status))


# -----------------------------------------
# RESUMEN
# -----------------------------------------
print("\nResumen:")
for r in results:
    print(f"{r[1]} ({r[0]}): {r[2]}")

print("\nFin de la auditoría.\n")
