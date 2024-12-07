
#!/bin/bash

# Variables de conexión a la base de datos
DB_USER="root"
DB_PASS="uv123"
DB_HOST="192.168.0.2"
DB_NAME="proyecto"

# Crear pipe con nombre para la comunicación
PIPE=/tmp/httpserver
trap "rm -f $PIPE" EXIT
mkfifo $PIPE

# Directorio para logs
LOGDIR="/tmp/httpserver_logs"
mkdir -p "$LOGDIR"

# Función para logging
log_debug() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOGDIR/debug.log"
    echo "[DEBUG] $1"
}

# Función para parsear peticiones HTTP y obtener el cuerpo
parse_request() {
    local content_length=0
    local boundary=""
    local content_type=""
    local temp_file=""

    while IFS= read -r line; do
        line=${line%$'\r'}
        [ -z "$line" ] && break

        if [[ $line =~ ^(GET|POST)\ /([^\ ]*)\ HTTP/[0-9.]+$ ]]; then
            METHOD=${BASH_REMATCH[1]}
            PATH_INFO=${BASH_REMATCH[2]}
            log_debug "Método: $METHOD, Ruta: $PATH_INFO"
        elif [[ $line =~ ^Content-Length:\ ([0-9]+)$ ]]; then
            content_length=${BASH_REMATCH[1]}
            log_debug "Content-Length: $content_length"
        elif [[ $line =~ ^Content-Type:\ (.*)$ ]]; then
            content_type=${BASH_REMATCH[1]}
            log_debug "Content-Type: $content_type"
            if [[ $content_type == *"multipart/form-data"* ]]; then
                boundary=$(echo "$content_type" | grep -o 'boundary=.*' | cut -d'=' -f2)
                log_debug "Boundary: $boundary"
            fi
        fi
    done

    if [ "$METHOD" = "POST" ] && [ $content_length -gt 0 ]; then
        if [[ $content_type == *"multipart/form-data"* ]]; then
            temp_file=$(mktemp)
            dd bs=1 count=$content_length 2>/dev/null > "$temp_file"
            awk -v boundary="$boundary" -v RS="--$boundary" '
                NR > 1 && NF {
                    if (index($0, "filename=")) {
                        split($0, arr, "\r\n\r\n")
                        print substr(arr[2], 1, length(arr[2])-2)
                    }
                }' "$temp_file" > "${temp_file}.extracted"
            REQUEST_BODY="${temp_file}.extracted"
            rm "$temp_file"
        else
            read -n $content_length REQUEST_BODY
        fi
    fi
}

# Función para enviar respuesta HTTP
send_response() {
    local status="$1"
    local content="$2"
    local content_type="${3:-text/plain; charset=utf-8}"

    printf "HTTP/1.1 %s\r\n" "$status"
    printf "Content-Type: %s\r\n" "$content_type"
    printf "Content-Length: %d\r\n" "${#content}"
    printf "Connection: close\r\n"
    printf "\r\n"
    printf "%s" "$content"
}

# Función para manejar procesos
handle_processes() {
    local action=$(echo "$PATH_INFO" | grep -oP 'accion=\K[^&]*' || echo '')
    local process_pid=$(echo "$PATH_INFO" | grep -oP 'pid=\K[^&]*' || echo '')

    if [ "$action" = "listar" ]; then
        local processes=$(ps aux | awk 'NR>1 {print $2 "," $11}' | tr '\n' ' ')
        send_response "200 OK" "PID,Proceso\n$processes"
    elif [ "$action" = "detener" ] && [ ! -z "$process_pid" ]; then
        if kill -15 "$process_pid" 2>/dev/null; then
            send_response "200 OK" "Proceso con PID $process_pid detenido exitosamente"
        else
            send_response "400 Bad Request" "No se pudo detener el proceso con PID $process_pid"
        fi
    else
        send_response "400 Bad Request" "Acción no válida. Use:\n- ?accion=listar\n- ?accion=detener&pid=NUMERO_PID"
    fi
}

# Función modificada para manejar creación de usuarios por URL
handle_create_user() {
    # Extraer datos de la URL (formato: /crear-usuario/datos?username=X&password=Y&fullname=Z&description=W)
    local params=${PATH_INFO#/crear-usuario/datos}
    params=${params#\?}
    
    local username=$(echo "$params" | grep -oP 'username=\K[^&]*' || echo '')
    local password=$(echo "$params" | grep -oP 'password=\K[^&]*' || echo '')
    local fullname=$(echo "$params" | grep -oP 'fullname=\K[^&]*' || echo '')
    local description=$(echo "$params" | grep -oP 'description=\K[^&]*' || echo '')

    # Decodificar URL encoding
    username=$(echo -e "${username//%/\\x}")
    password=$(echo -e "${password//%/\\x}")
    fullname=$(echo -e "${fullname//%/\\x}")
    description=$(echo -e "${description//%/\\x}")

    if [ -z "$username" ] || [ -z "$password" ]; then
        send_response "400 Bad Request" "Error: Se requiere username y password en la URL"
        return
    fi

    useradd -m "$username" 2>/dev/null
    if [ $? -ne 0 ]; then
        send_response "500 Internal Server Error" "Error: No se pudo crear el usuario $username"
        return
    fi

    echo "$username:$password" | chpasswd 2>/dev/null
    if [ $? -ne 0 ]; then
        send_response "500 Internal Server Error" "Error: No se pudo establecer la contraseña"
        return
    fi

    if [ -n "$fullname" ]; then
        chfn -f "$fullname" "$username" 2>/dev/null
    fi

    if [ -n "$description" ]; then
        usermod -c "$description" "$username" 2>/dev/null
    fi

    send_response "200 OK" "¡Usuario $username creado exitosamente!"
}

# Función para obtener usuarios y llaves públicas
handle_get_users() {
    if [ "$METHOD" != "GET" ]; then
        send_response "405 Method Not Allowed" "Error: Método no permitido. Use GET"
        return
    fi

    local result=$(mysql -u$DB_USER -p$DB_PASS -h$DB_HOST -D$DB_NAME -e \
        "SELECT Usuario, LlavePublica FROM UsuariosLLaves" -B -N)

    if [ -z "$result" ]; then
        send_response "404 Not Found" "No se encontraron usuarios"
        return
    fi

    local json_response="["
    while IFS=$'\t' read -r usuario llave_publica; do
        json_response+="{\"usuario\":\"$usuario\", \"llave_publica\":\"$llave_publica\"},"
    done <<< "$result"

    json_response="${json_response%,}]"
    send_response "200 OK" "$json_response" "application/json"
}

# Limpiar logs anteriores
echo "" > "$LOGDIR/debug.log"
log_debug "Iniciando servidor..."

# Crear directorio para subidas si no existe
mkdir -p uploads
chmod 777 uploads

# Bucle principal del servidor
echo "Iniciando servidor HTTP en el puerto 31111..."
while true; do
    nc -l -p 31111 < $PIPE | (
        parse_request

        case "$PATH_INFO" in
            procesos*|procesos\?*)
                handle_processes
                ;;
            crear-usuario/datos*)
                handle_create_user
                ;;
            "get-usuarios")
                handle_get_users
                ;;
            *)
                send_response "404 Not Found" "Error: Ruta no encontrada: $PATH_INFO"
                ;;
        esac
    ) > $PIPE
done

