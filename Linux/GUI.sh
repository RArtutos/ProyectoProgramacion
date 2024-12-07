#!/bin/bash
# Configuración de la dirección del servidor Windows
httpWindows="192.168.0.1:31112"


# Variables para la conexión con mysql
DB_HOST="192.168.0.2"
DB_USER="root"
DB_PASS="uv123"
DB_NAME="proyecto"

# Variables de configuración
SHARED_FOLDER="//192.168.0.1/proyecto/"  # Ruta del recurso compartido
USERNAME="proyecto"                   # Usuario de SMB
PASSWORD="1234"  


# Función para mostrar mensajes de error
mostrar_error() {
    dialog --title "Error" --msgbox "$1" 8 40
}

# Función para mostrar mensajes de éxito
Bmostrar_exito() {
    dialog --title "Éxito" --msgbox "$1" 8 40
}

# Función para formatear procesos JSON
formatear_procesos() {
    local temp_file=$(mktemp)

    # Usar jq para extraer el ID y el nombre de los procesos
    jq -r '.[] | "\(.Id) \(.Name)"' <<< "$1" > "$temp_file"

    echo "$temp_file"
}

mostrar_procesos() {
    while true; do
        # Obtener lista de procesos del servidor Windows
        procesos=$(curl -s "http://192.168.0.1:31112/procesos?accion=listar" --http0.9)

        # Formatear procesos y crear archivo temporal
        temp_file=$(formatear_procesos "$procesos")

        if [ ! -s "$temp_file" ]; then
            mostrar_error "No se pudieron obtener los procesos"
            rm "$temp_file"
            return
        fi

        # Preparar los elementos para el diálogo
        menu_items=()
        while read -r pid name; do
            menu_items+=("$pid" "$name")
        done < "$temp_file"

        # Mostrar procesos en dialog
        seleccion=$(dialog --title "Lista de Procesos" \
                          --menu "Seleccione un proceso:" 20 60 10 \
                          "${menu_items[@]}" \
                          "R" "Refrescar" \
                          "S" "Detener proceso" \
                          "X" "Salir" \
                          2>&1 >/dev/tty)

        case $seleccion in
            "R")
                rm "$temp_file"
                continue
                ;;

            "S")
                pid=$(dialog --inputbox "Ingrese el PID del proceso a detener:" 8 40 2>&1 >/dev/tty)
                if [ -n "$pid" ]; then
                    curl "http://$httpWindows/procesos?accion=detener&pid=$pid" --http0.9
                    mostrar_exito "Proceso detenido"
                fi
                ;;

            "X"|"")
                rm "$temp_file"
                return
                ;;

            *)  # Si se seleccionó un PID específico
                if [ -n "$seleccion" ]; then
                    if dialog --yesno "¿Desea detener el proceso $seleccion?" 8 40; then
                        curl "http://$httpWindows/procesos?accion=detener&id=$seleccion" --http0.9
                        mostrar_exito "Proceso detenido"
                    fi
                fi
                ;;
        esac
        rm "$temp_file"
    done
}



subir_archivo() {
    local SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

    # Función para navegar directorios con contadores separados para carpetas y archivos
    navegar_directorios() {
        local current_dir="$1"
        local selection

        while true; do
            # Arrays para almacenar información
            declare -a options
            declare -a paths
            declare -a types
            local total_count=0

            # Mostrar directorio actual en la parte superior
            local current_path_display=$(echo "$current_dir" | sed "s|$HOME|~|")

            # Agregar opción para subir un nivel si no estamos en la raíz
            if [ "$current_dir" != "/" ]; then
                options[$total_count]="[📁] .."
                paths[$total_count]="$current_dir/.."
                types[$total_count]="dir"
                ((total_count++))
            fi

            # Listar directorios primero
            while IFS= read -r -d $'\0' d; do
                options[$total_count]="[📁] $(basename "$d")"
                paths[$total_count]="$d"
                types[$total_count]="dir"
                ((total_count++))
            done < <(find "$current_dir" -maxdepth 1 -mindepth 1 -type d -print0 | sort -z)

            # Luego listar archivos
            while IFS= read -r -d $'\0' f; do
                options[$total_count]="[📄] $(basename "$f")"
                paths[$total_count]="$f"
                types[$total_count]="file"
                ((total_count++))
            done < <(find "$current_dir" -maxdepth 1 -mindepth 1 -type f -print0 | sort -z)

            # Crear opciones para dialog
            local dialog_options=""
            for ((i=0; i<$total_count; i++)); do
                dialog_options="$dialog_options $((i+1)) \"${options[$i]}\""
            done

            # Mostrar diálogo con scroll si hay muchos elementos
            selection=$(eval dialog --clear --title \"Navegador de Archivos\" \
                            --menu \"Directorio actual: $current_path_display\" \
                            20 70 15 \
                            $dialog_options \
                            2>&1 >/dev/tty)

            if [ $? -ne 0 ]; then
                return 1
            fi

            # Ajustar selección para índice base 0
            ((selection--))

            if [ "${types[$selection]}" = "dir" ]; then
                current_dir=$(realpath "${paths[$selection]}")
            else
                echo "${paths[$selection]}"
                return 0
            fi
        done
    }

    # Iniciar navegación desde el directorio del script
    local ARCHIVO=$(navegar_directorios "$SCRIPT_DIR")

    if [ $? -ne 0 ] || [ -z "$ARCHIVO" ]; then
        clear
        return 1
    fi

    # Verificar si el archivo existe
    if [ ! -f "$ARCHIVO" ]; then
        dialog --title "Error" --msgbox "El archivo seleccionado no existe" 8 40
        clear
        return 1
    fi

    # Obtener el nombre base del archivo
    local ARCHIVO_BASE=$(basename "$ARCHIVO")

    # Mostrar diálogo de progreso
(
    echo "XXX"
    echo "0"
    echo "Preparando para subir el archivo..."
    echo "XXX"
    sleep 1

    # Realizar la subida del archivo usando smbclient
    RESPONSE=$(echo "$PASSWORD" | smbclient $SHARED_FOLDER -U "$USERNAME" -c "put \"$ARCHIVO\" \"$ARCHIVO_BASE\"")

    echo "XXX"
    echo "100"
    echo "Subida completada"
    echo "XXX"
    sleep 1
) | dialog --title "Subiendo Archivo" --gauge "Iniciando subida..." 8 50 0

# Verificar si la subida fue exitosa
if [[ $? -eq 0 ]]; then
    echo "Archivo subido exitosamente"
else
    echo "Error al subir el archivo. Por favor, verifique los detalles."
fi

clear
}


# Función para crear usuario
crear_usuario() {
    # Obtener datos mediante dialog
    temp_file=$(mktemp)
    dialog --title "Crear Usuario" \
           --form "Ingrese los datos del usuario:" 15 50 4 \
           "Usuario:" 1 1 "" 1 20 25 0 \
           "Nombre:" 2 1 "" 2 20 25 0 \
           "Descripción:" 3 1 "" 3 20 25 0 \
           "Contraseña:" 4 1 "" 4 20 25 0 \
           2> "$temp_file"

    if [ $? -eq 0 ]; then
        # Leer los valores del archivo temporal
        usuario=$(sed -n '1p' "$temp_file")
        nombre=$(sed -n '2p' "$temp_file")
        descripcion=$(sed -n '3p' "$temp_file")
        password=$(sed -n '4p' "$temp_file")

        # Validar campos obligatorios
        if [ -z "$usuario" ] || [ -z "$nombre" ] || [ -z "$password" ]; then
            mostrar_error "Todos los campos obligatorios deben ser llenados"
            rm "$temp_file"
            return
        fi

        if id "$usuario" &>/dev/null; then
            mostrar_error "El usuario '$usuario' ya existe en el sistema"
            rm "$temp_file"
            return
        fi

        # Crear usuario en el sistema local
        useradd -m -c "$nombre" -d "/home/$usuario" "$usuario"
        echo "$usuario:$password" | chpasswd

        # Enviar solicitud HTTP al servidor Windows
        curl -X POST \
             -H "Content-Type: application/json" \
             -d "{\"username\":\"$usuario\",\"password\":\"$password\",\"fullname\":\"$nombre\",\"description\":\"$descripcion\"}" \
             "http://$httpWindows/crear-usuario" --http0.9

        mostrar_exito "Usuario creado exitosamente"
    fi
    rm "$temp_file"
}

generar_llaves() {
    # Verificar si el archivo /etc/passwd existe
    if [ ! -f /etc/passwd ]; then
        dialog --msgbox "El archivo /etc/passwd no se encuentra." 6 40
        return 1
    fi

    # Obtener lista de usuarios locales del sistema, solo los usuarios humanos (UID >= 1000)
    usuarios=$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd)

    # Verificar si no se encontraron usuarios locales
    if [ -z "$usuarios" ]; then
        dialog --msgbox "No se encontraron usuarios locales en el sistema." 6 40
        return 1
    fi

    # Crear el array para la lista de usuarios para dialog
    menu=()
    for usuario in $usuarios; do
        menu+=("$usuario" "$usuario")
    done

    # Usar dialog para seleccionar un usuario
    usuario=$(dialog --stdout --menu "Selecciona un usuario" 15 50 8 "${menu[@]}")

    # Verificar si el usuario seleccionó algo
    if [ -z "$usuario" ]; then
        dialog --msgbox "No se ha seleccionado un usuario." 6 40
        return 1
    fi

    # Verificar si la tabla existe, si no, crearla
    mysql -u$DB_USER -p$DB_PASS -h$DB_HOST -e \
    "CREATE TABLE IF NOT EXISTS UsuariosLLaves (
        id INT AUTO_INCREMENT PRIMARY KEY,
        Usuario VARCHAR(255) UNIQUE NOT NULL,
        LlavePublica TEXT NOT NULL,
        LlavePrivada TEXT NOT NULL
    )" $DB_NAME

    # Verificar si el usuario ya tiene llaves en la base de datos
    resultado=$(mysql -u$DB_USER -p$DB_PASS -h$DB_HOST -e "SELECT COUNT(*) FROM UsuariosLLaves WHERE Usuario = '$usuario'" -s -N $DB_NAME)

    if [[ $resultado -gt 0 ]]; then
        dialog --msgbox "El usuario ya tiene llaves generadas." 6 40
        return 1
    fi

    # Generar las llaves PEM (privada y pública) con OpenSSL
    openssl genpkey -algorithm RSA -out /tmp/$usuario.key -pkeyopt rsa_keygen_bits:2048

    # Extraer la clave pública en formato PEM desde la clave privada
    openssl rsa -pubout -in /tmp/$usuario.key -out /tmp/$usuario.pub

    # Leer las llaves generadas
    llave_privada=$(cat /tmp/$usuario.key)
    llave_publica=$(cat /tmp/$usuario.pub)

    # Guardar las llaves en la base de datos
    mysql -u$DB_USER -p$DB_PASS -h$DB_HOST -e \
    "INSERT INTO UsuariosLLaves (Usuario, LlavePublica, LlavePrivada) VALUES ('$usuario', '$llave_publica', '$llave_privada')" $DB_NAME

    dialog --msgbox "Llaves generadas y almacenadas exitosamente para el usuario $usuario." 6 40
    return 0
}






encriptar_archivo() {
    local SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
    local ENCRYPTED_DIR="$SCRIPT_DIR/encriptados"
    mkdir -p "$ENCRYPTED_DIR"

    # Obtener lista de usuarios
    local USERS_LIST=$(curl -s "http://$httpWindows/get-usuarios")
    local CURL_STATUS=$?

    if [ $CURL_STATUS -ne 0 ]; then
        dialog --title "Error" --msgbox "No se pudo conectar al servidor" 8 40
        return 1
    fi

    # Eliminar comillas y espacios de la lista de usuarios
    USERS_LIST=$(echo "$USERS_LIST" | sed 's/"//g' | tr -s '[:space:]' '\n')

    # Verificar si hay usuarios
    if [ -z "$USERS_LIST" ]; then
        dialog --title "Error" --msgbox "No hay usuarios disponibles" 8 40
        return 1
    fi

    # Crear lista de usuarios para dialog
    local users_options=""
    local counter=1
    for usuario in $USERS_LIST; do
        users_options="$users_options $counter \"$usuario\""
        ((counter++))
    done

    # Seleccionar usuario
    local SELECTED_USER=$(eval dialog --clear --title \"Seleccionar Usuario\" \
                          --menu \"Elija un usuario para encriptar:\" 15 40 5 \
                          $users_options \
                          2>&1 >/dev/tty)

    if [ $? -ne 0 ]; then
        clear
        return 1
    fi

    # Obtener el usuario seleccionado
    local USUARIO=$(echo "$USERS_LIST" | sed -n "${SELECTED_USER}p")
    rm "$temp_users_file"

    # Obtener y guardar la llave pública del usuario directamente en un archivo temporal
    local TEMP_KEY_FILE=$(mktemp)
    curl -s "http://$httpWindows/get-usuarios?get-key=$USUARIO" > "$TEMP_KEY_FILE"
    
    # Limpiar el archivo de llave de las comillas
    sed -i 's/^"\(.*\)"$/\1/' "$TEMP_KEY_FILE"

    if [ ! -s "$TEMP_KEY_FILE" ]; then
        dialog --title "Error" --msgbox "No se pudo obtener la llave pública del usuario" 8 50
        rm "$TEMP_KEY_FILE"
        return 1
    fi

    # Mostrar información del usuario seleccionado
    dialog --title "Usuario Seleccionado" \
           --msgbox "Se usará la llave pública del usuario: $USUARIO" 8 50

    # Función para navegar directorios con contadores separados para carpetas y archivos
    navegar_directorios() {
        local current_dir="$1"
        local selection

        while true; do
            # Arrays para almacenar información
            declare -a options
            declare -a paths
            declare -a types
            local total_count=0

            # Mostrar directorio actual en la parte superior
            local current_path_display=$(echo "$current_dir" | sed "s|$HOME|~|")

            # Agregar opción para subir un nivel si no estamos en la raíz
            if [ "$current_dir" != "/" ]; then
                options[$total_count]="[📁] .."
                paths[$total_count]="$current_dir/.."
                types[$total_count]="dir"
                ((total_count++))
            fi

            # Listar directorios primero
            while IFS= read -r -d $'\0' d; do
                options[$total_count]="[📁] $(basename "$d")"
                paths[$total_count]="$d"
                types[$total_count]="dir"
                ((total_count++))
            done < <(find "$current_dir" -maxdepth 1 -mindepth 1 -type d -print0 | sort -z)

            # Luego listar archivos
            while IFS= read -r -d $'\0' f; do
                options[$total_count]="[📄] $(basename "$f")"
                paths[$total_count]="$f"
                types[$total_count]="file"
                ((total_count++))
            done < <(find "$current_dir" -maxdepth 1 -mindepth 1 -type f -print0 | sort -z)

            # Crear opciones para dialog
            local dialog_options=""
            for ((i=0; i<$total_count; i++)); do
                dialog_options="$dialog_options $((i+1)) \"${options[$i]}\""
            done

            # Mostrar diálogo con scroll si hay muchos elementos
            selection=$(eval dialog --clear --title \"Navegador de Archivos\" \
                            --menu \"Directorio actual: $current_path_display\" \
                            20 70 15 \
                            $dialog_options \
                            2>&1 >/dev/tty)

            if [ $? -ne 0 ]; then
                return 1
            fi

            # Ajustar selección para índice base 0
            ((selection--))

            if [ "${types[$selection]}" = "dir" ]; then
                current_dir=$(realpath "${paths[$selection]}")
            else
                echo "${paths[$selection]}"
                return 0
            fi
        done
    }

    # Iniciar navegación desde el directorio home del usuario
    local ARCHIVO=$(navegar_directorios "$HOME")

    if [ $? -ne 0 ] || [ -z "$ARCHIVO" ]; then
        clear
        return 1
    fi

    # Verificar si el archivo existe
    if [ ! -f "$ARCHIVO" ]; then
        dialog --title "Error" --msgbox "El archivo seleccionado no existe" 8 40
        clear
        return 1
    fi

    # Crear nombre del archivo encriptado
    local ARCHIVO_BASE=$(basename "$ARCHIVO")
    local ARCHIVO_ENCRIPTADO="$ENCRYPTED_DIR/${ARCHIVO_BASE}_${USUARIO}.enc"

    # Encriptar el archivo usando openssl
    openssl rsautl -encrypt \
        -inkey "$TEMP_KEY_FILE" \
        -pubin \
        -in "$ARCHIVO" \
        -out "$ARCHIVO_ENCRIPTADO" 2>/dev/null

    local ENCRYPT_STATUS=$?
    rm "$TEMP_KEY_FILE"  # Limpiar archivo temporal

    if [ $ENCRYPT_STATUS -eq 0 ]; then
        dialog --title "Éxito" \
               --msgbox "Archivo encriptado guardado como:\n$ARCHIVO_ENCRIPTADO" 8 60
    else
        dialog --title "Error" \
               --msgbox "Error al encriptar el archivo. Asegúrese de que el archivo no sea muy grande para encriptar con RSA." 8 60
    fi

    clear
}


















#!/bin/bash

# Configuración de MySQL
DB_HOST="localhost"
DB_USER="usuario"
DB_PASS="contraseña"
DB_NAME="basedatos"

# Función para limpiar formato de llave
limpiar_formato_llave() {
    local contenido="$1"
    echo "$contenido" | sed 's/\\n/\n/g'  # Reemplaza \n por saltos de línea reales
}

# Función para manejar archivos temporales de manera segura
crear_archivo_temporal() {
    local temp_file
    temp_file=$(mktemp) || {
        dialog --title "Error" --msgbox "No se pudo crear el archivo temporal" 8 40
        return 1
    }
    
    # Asegurar que el archivo temporal se elimine al salir
    trap 'rm -f "$temp_file"' EXIT
    
    # Establecer permisos restrictivos
    chmod 600 "$temp_file"
    
    echo "$temp_file"
}

# Función para obtener llave privada de MySQL
obtener_llave_privada() {
    local usuario="$1"
    local archivo_salida="$2"
    
    # Obtener llave privada de MySQL
    local llave_privada=$(mysql -h "localhost" -u "root" -p"uv123" "proyecto" -N -e \
        "SELECT LlavePrivada FROM UsuariosLLaves WHERE Usuario='$usuario';")
    
    if [ -z "$llave_privada" ]; then
        return 1
    fi
    
    # Limpiar formato y guardar en archivo
    limpiar_formato_llave "$llave_privada" > "$archivo_salida"
    return 0
}

# Función para navegar directorios
navegar_directorios() {
    local current_dir="$(dirname "$(readlink -f "$0")")"  # Comenzar desde el directorio del script
    local selection

    while true; do
        declare -a options
        declare -a paths
        declare -a types
        local total_count=0

        local current_path_display=$(echo "$current_dir" | sed "s|$HOME|~|")

        if [ "$current_dir" != "/" ]; then
            options[$total_count]="[📁] .."
            paths[$total_count]="$current_dir/.."
            types[$total_count]="dir"
            ((total_count++))
        fi

        while IFS= read -r -d $'\0' d; do
            options[$total_count]="[📁] $(basename "$d")"
            paths[$total_count]="$d"
            types[$total_count]="dir"
            ((total_count++))
        done < <(find "$current_dir" -maxdepth 1 -mindepth 1 -type d -print0 | sort -z)

        while IFS= read -r -d $'\0' f; do
            options[$total_count]="[📄] $(basename "$f")"
            paths[$total_count]="$f"
            types[$total_count]="file"
            ((total_count++))
        done < <(find "$current_dir" -maxdepth 1 -mindepth 1 -type f -print0 | sort -z)

        local dialog_options=""
        for ((i=0; i<$total_count; i++)); do
            dialog_options="$dialog_options $((i+1)) \"${options[$i]}\""
        done

        selection=$(eval dialog --clear --title \"Navegador de Archivos\" \
                        --menu \"Directorio actual: $current_path_display\" \
                        20 70 15 \
                        $dialog_options \
                        2>&1 >/dev/tty)

        if [ $? -ne 0 ]; then
            return 1
        fi

        ((selection--))

        if [ "${types[$selection]}" = "dir" ]; then
            current_dir=$(realpath "${paths[$selection]}")
        else
            echo "${paths[$selection]}"
            return 0
        fi
    done
}

# Función para desencriptar archivo
desencriptar_archivo() {
    local SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
    local DECRYPTED_DIR="$SCRIPT_DIR/desencriptados"
    mkdir -p "$DECRYPTED_DIR"

    # Seleccionar archivo a desencriptar
    local ARCHIVO=$(navegar_directorios)
    if [ $? -ne 0 ] || [ -z "$ARCHIVO" ]; then
        return 1
    fi

    # Obtener lista de usuarios desde MySQL
    local USERS_LIST=$(mysql -h "localhost" -u "root" -p"uv123" "proyecto" -N -e "SELECT Usuario FROM UsuariosLLaves;")

    if [ -z "$USERS_LIST" ]; then
        dialog --title "Error" --msgbox "No hay usuarios disponibles" 8 40
        return 1
    fi

    # Crear lista de usuarios para dialog
    local users_options=""
    local counter=1
    while read -r usuario; do
        users_options="$users_options $counter \"$usuario\""
        ((counter++))
    done <<< "$USERS_LIST"

    # Seleccionar usuario
    local SELECTED_USER=$(eval dialog --clear --title \"Seleccionar Usuario\" \
                          --menu \"Elija un usuario para desencriptar:\" 15 40 5 \
                          $users_options \
                          2>&1 >/dev/tty)

    if [ $? -ne 0 ]; then
        return 1
    fi

    # Obtener el usuario seleccionado y su llave privada
    local USUARIO=$(echo "$USERS_LIST" | sed -n "${SELECTED_USER}p")
    local TEMP_KEY_FILE=$(crear_archivo_temporal)
    
    if ! obtener_llave_privada "$USUARIO" "$TEMP_KEY_FILE"; then
        dialog --title "Error" --msgbox "No se pudo obtener la llave privada" 8 40
        return 1
    fi

    # Crear nombre del archivo desencriptado
    local ARCHIVO_BASE=$(basename "$ARCHIVO" .enc)
    local ARCHIVO_DESENCRIPTADO="$DECRYPTED_DIR/${ARCHIVO_BASE}_decrypted"

    # Desencriptar archivo
    openssl rsautl -decrypt \
        -inkey "$TEMP_KEY_FILE" \
        -in "$ARCHIVO" \
        -out "$ARCHIVO_DESENCRIPTADO" 2>/dev/null

    if [ $? -eq 0 ]; then
        dialog --title "Éxito" \
               --msgbox "Archivo desencriptado guardado como:\n$ARCHIVO_DESENCRIPTADO" 8 60
    else
        dialog --title "Error" \
               --msgbox "Error al desencriptar el archivo" 8 40
        rm -f "$ARCHIVO_DESENCRIPTADO"
    fi
}

# Función para firmar archivo
firmar_archivo() {
    local SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
    local SIGNED_DIR="$SCRIPT_DIR/firmados"
    mkdir -p "$SIGNED_DIR"

    # Obtener lista de usuarios desde MySQL
    local USERS_LIST=$(mysql -h "localhost" -u "root" -p"uv123" "proyecto" -N -e "SELECT Usuario FROM UsuariosLLaves;")

    if [ -z "$USERS_LIST" ]; then
        dialog --title "Error" --msgbox "No hay usuarios disponibles" 8 40
        return 1
    fi

    # Crear lista de usuarios para dialog
    local users_options=""
    local counter=1
    while read -r usuario; do
        users_options="$users_options $counter \"$usuario\""
        ((counter++))
    done <<< "$USERS_LIST"

    # Seleccionar usuario
    local SELECTED_USER=$(eval dialog --clear --title \"Seleccionar Usuario\" \
                          --menu \"Elija un usuario para firmar:\" 15 40 5 \
                          $users_options \
                          2>&1 >/dev/tty)

    if [ $? -ne 0 ]; then
        return 1
    fi

    # Obtener el usuario seleccionado y su llave privada
    local USUARIO=$(echo "$USERS_LIST" | sed -n "${SELECTED_USER}p")
    local TEMP_KEY_FILE=$(crear_archivo_temporal)
    
    if ! obtener_llave_privada "$USUARIO" "$TEMP_KEY_FILE"; then
        dialog --title "Error" --msgbox "No se pudo obtener la llave privada" 8 40
        return 1
    fi

    # Seleccionar archivo a firmar
    local ARCHIVO=$(navegar_directorios)
    if [ $? -ne 0 ] || [ -z "$ARCHIVO" ]; then
        return 1
    fi

    # Crear nombre del archivo de firma, agregando el sufijo del usuario
    local ARCHIVO_BASE=$(basename "$ARCHIVO")
    local ARCHIVO_FIRMA="$SIGNED_DIR/${ARCHIVO_BASE%.txt}_$USUARIO.sign"

    # Copiar el archivo original y el firmado al directorio 'firmados'
    cp "$ARCHIVO" "$SIGNED_DIR/$(basename "$ARCHIVO")"

    # Firmar archivo
    openssl dgst -sha256 -sign "$TEMP_KEY_FILE" \
        -out "$ARCHIVO_FIRMA" "$ARCHIVO" 2>/dev/null

    if [ $? -eq 0 ]; then
        dialog --title "Éxito" \
               --msgbox "Archivo firmado guardado como:\n$ARCHIVO_FIRMA\nArchivo original guardado como:\n$SIGNED_DIR/$(basename "$ARCHIVO")" 8 60
    else
        dialog --title "Error" \
               --msgbox "Error al firmar el archivo" 8 40
        rm -f "$ARCHIVO_FIRMA"
    fi
}


# Función para verificar firma
verificar_firma() {
    # Seleccionar archivo firmado (.sig)
    dialog --title "Selección" --msgbox "Seleccione el archivo firmado" 8 40
    local ARCHIVO_FIRMA=$(navegar_directorios)
    if [ $? -ne 0 ] || [ -z "$ARCHIVO_FIRMA" ]; then
        return 1
    fi

    # Obtener lista de usuarios del servidor HTTP
    local USERS_LIST=$(curl -s "http://192.168.0.1:31112/get-usuarios")
    USERS_LIST=$(echo "$USERS_LIST" | sed 's/"//g' | tr -s '[:space:]' '\n')

    if [ -z "$USERS_LIST" ]; then
        dialog --title "Error" --msgbox "No se pudo obtener la lista de usuarios" 8 40
        return 1
    fi

    # Crear lista de usuarios para dialog
    local users_options=""
    local counter=1
    while read -r usuario; do
        users_options="$users_options $counter \"$usuario\""
        ((counter++))
    done <<< "$USERS_LIST"

    # Seleccionar usuario
    local SELECTED_USER=$(eval dialog --clear --title \"Seleccionar Usuario\" \
                          --menu \"Elija un usuario para verificar la firma:\" 15 40 5 \
                          $users_options \
                          2>&1 >/dev/tty)

    if [ $? -ne 0 ]; then
        return 1
    fi

    # Obtener el usuario y su llave pública
    local USUARIO=$(echo "$USERS_LIST" | sed -n "${SELECTED_USER}p")
    local TEMP_KEY_FILE=$(crear_archivo_temporal)

    # Obtener llave pública del servidor
    curl -s "http://192.168.0.1:31112/get-usuarios?get-key=$USUARIO" > "$TEMP_KEY_FILE"
    sed -i 's/^"\(.*\)"$/\1/' "$TEMP_KEY_FILE"
    limpiar_formato_llave "$(cat "$TEMP_KEY_FILE")" > "${TEMP_KEY_FILE}.clean"
    mv "${TEMP_KEY_FILE}.clean" "$TEMP_KEY_FILE"

    if [ ! -s "$TEMP_KEY_FILE" ]; then
        dialog --title "Error" --msgbox "No se pudo obtener la llave pública" 8 40
        return 1
    fi

    # Seleccionar archivo firmado (verificarlo)
    dialog --title "Selección" --msgbox "Seleccione el archivo firmado a verificar" 8 40
    local ARCHIVO=$(navegar_directorios)
    if [ $? -ne 0 ] || [ -z "$ARCHIVO" ]; then
        return 1
    fi

    # Verificar firma
    openssl dgst -sha256 -verify "$TEMP_KEY_FILE" \
        -signature "$ARCHIVO_FIRMA" "$ARCHIVO" > /dev/null 2>&1

    if [ $? -eq 0 ]; then
        dialog --title "Verificación" --msgbox "La firma es válida" 8 40
    else
        dialog --title "Verificación" --msgbox "La firma NO es válida" 8 40
    fi
}













# Menú principal
while true; do
    opcion=$(dialog --title "Sistema de Archivos Seguro" \
                    --menu "Seleccione una opción:" 20 60 10 \
                    1 "Usuarios" \
                    2 "Archivos" \
                    3 "Seguridad" \
                    4 "Procesos" \
                    5 "Salir" \
                    2>&1 >/dev/tty)

    case $opcion in
        1)  # Menú Usuarios
            sub_opcion=$(dialog --title "Usuarios" \
                               --menu "Seleccione una opción:" 15 50 2 \
                               1 "Crear Usuario" \
                               2 "Generar Llaves" \
                               2>&1 >/dev/tty)
            case $sub_opcion in
                1) crear_usuario ;;
                2) generar_llaves ;;
            esac
            ;;
        2)  # Menú Archivos
            sub_opcion=$(dialog --title "Archivos" \
                               --menu "Seleccione una opción:" 15 50 1 \
                               1 "Subir Archivo" \
                               2>&1 >/dev/tty)
            case $sub_opcion in
                1) subir_archivo ;;
            esac
            ;;
        3)  # Menú Seguridad
            sub_opcion=$(dialog --title "Seguridad" \
                               --menu "Seleccione una opción:" 15 50 4 \
                               1 "Encriptar Archivo" \
                               2 "Desencriptar Archivo" \
                               3 "Firmar Archivo" \
                               4 "Verificar Firma" \
                               2>&1 >/dev/tty)
            case $sub_opcion in
                1) encriptar_archivo ;;
                2) desencriptar_archivo ;;
                3) firmar_archivo ;;
                4) verificar_firma ;;
            esac
            ;;
        4) mostrar_procesos ;;
        5|"") clear; exit 0 ;;
    esac
done




