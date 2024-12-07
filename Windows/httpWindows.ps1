# Configuración básica del servidor
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://*:31112/") # Cambia el puerto si es necesario
$listener.Start()
Write-Host "Servidor iniciado en puerto 31112..."


$connectionString = "Server=localhost;Database=proyecto;Integrated Security=True;"

function ObtenerUsuarios($context) {
    try {
        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
        $connection.Open()

        $query = "SELECT Usuario, LlavePublica FROM UsuariosLLaves"
        $command = New-Object System.Data.SqlClient.SqlCommand($query, $connection)
        $reader = $command.ExecuteReader()

        # Obtener el parámetro 'get-key' de la URL
        $usuarioParam = $context.Request.QueryString["get-key"]

        # Crear el contenido en memoria
        $pemContent = ""

        if ($usuarioParam) {
            $usuarioEncontrado = $false

            while ($reader.Read()) {
                $usuario = $reader["Usuario"].ToString().Trim().Replace('"', '""')
                $llave = $reader["LlavePublica"].ToString().Trim().Replace('"', '""')

                if ($usuario -eq $usuarioParam) {
                    # Si la llave ya está en formato PEM, solo se devuelve tal cual
                    $pemContent = $llave
                    
                    $usuarioEncontrado = $true
                    break
                }
            }

            if (-not $usuarioEncontrado) {
                $pemContent = "error,mensaje`n`"Usuario no encontrado`",`"$usuarioParam`""
                $context.Response.StatusCode = 404
            }
        }
        else {
            # Si no se pasa el parámetro 'get-key', devolver solo los usuarios
            while ($reader.Read()) {
                $usuario = $reader["Usuario"].ToString().Trim().Replace('"', '""')
                $pemContent += "`"$usuario`"`n"
            }
        }

        # Configurar la respuesta con el contenido adecuado
        $context.Response.ContentType = "text/plain"  # Cambiar a texto plano para la llave pública
        $context.Response.Headers.Add("Content-Disposition", "attachment; filename=llave_publica.pem")
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($pemContent)
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    catch {
        $errorContent = "error,mensaje`n`"Error al obtener usuarios`",`"$($_.Exception.Message)`""
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($errorContent)
        $context.Response.StatusCode = 500
        $context.Response.ContentType = "text/csv"
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    finally {
        if ($reader) { $reader.Close() }
        if ($connection) { $connection.Close() }
        if ($context.Response.OutputStream) {
            $context.Response.OutputStream.Close()
        }
    }
}





# Funciones para las rutas
function SubirArchivo($context) {
    try {
        $inputStream = $context.Request.InputStream
        $fileName = $context.Request.QueryString["nombre"] # Nombre del archivo
        if (-not $fileName) { $fileName = "archivo_subido.bin" }
        
        # Asegurarse de que el directorio uploads existe
        $uploadsDir = Join-Path -Path (Get-Location) -ChildPath "uploads"
        if (-not (Test-Path $uploadsDir)) {
            New-Item -ItemType Directory -Path $uploadsDir | Out-Null
        }
        
        $outputPath = Join-Path -Path $uploadsDir -ChildPath $fileName
        
        # Crear el archivo y copiar el contenido
        $buffer = New-Object byte[] 8192
        $fs = [System.IO.File]::Create($outputPath)
        
        do {
            $read = $inputStream.Read($buffer, 0, $buffer.Length)
            if ($read -gt 0) {
                $fs.Write($buffer, 0, $read)
            }
        } while ($read -gt 0)
        
        $fs.Close()
        $inputStream.Close()
        
        # Enviar respuesta
        $response = "Archivo recibido: $fileName"
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    catch {
        # Manejar error
        $errorResponse = "Error al procesar el archivo: " + $_.Exception.Message
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($errorResponse)
        $context.Response.StatusCode = 500
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    finally {
        if ($fs) { $fs.Dispose() }
        if ($context.Response.OutputStream) {
            $context.Response.OutputStream.Close()
        }
    }
}

function CrearUsuario($context) {
    try {
        $reader = New-Object System.IO.StreamReader($context.Request.InputStream)
        $body = $reader.ReadToEnd()
        $data = $body | ConvertFrom-Json
        $username = $data.username
        $password = $data.password
        $fullname = $data.fullname
        $description = $data.description

        # Crear el usuario
        net user $username $password /add 2>&1 | Out-Null

        # Si se desea, se podría agregar la descripción y nombre completo al perfil del usuario.
        # Aquí solo los imprimimos por ahora:
        Write-Host "Usuario: $username"
        Write-Host "Nombre completo: $fullname"
        Write-Host "Descripción: $description"

        # Respuesta
        $response = "Usuario $username creado exitosamente."
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    catch {
        $errorResponse = "Error al crear usuario: " + $_.Exception.Message
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($errorResponse)
        $context.Response.StatusCode = 500
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    finally {
        if ($context.Response.OutputStream) {
            $context.Response.OutputStream.Close()
        }
    }
}

function GestionarProcesos($context) {
    try {
        $action = $context.Request.QueryString["accion"]
        $processID = $context.Request.QueryString["id"]
        $response = ""
        
        if ($action -eq "listar") {
            $processes = Get-Process | Select-Object -Property Name, Id | ConvertTo-Json
            $response = $processes
        }
        elseif ($action -eq "detener" -and $processID) {
            Stop-Process -id $processID -Force
            $response = "Proceso $processID detenido exitosamente."
            #$textSueldo.Add_KeyPress({
            #  $PSItem.Handled = ![Char]::IsDigit($PSItem.KeyChar) -and ![char]::IsControl($PSItem.KeyChar);
            #})
        }
        else {
            $response = "Acción no válida. Use ?accion=listar o ?accion=detener&id=proceso"
        }
        
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    catch {
        $errorResponse = "Error en gestión de procesos: " + $_.Exception.Message
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($errorResponse)
        $context.Response.StatusCode = 500
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    finally {
        if ($context.Response.OutputStream) {
            $context.Response.OutputStream.Close()
        }
    }
}

function RecibirCredenciales($context) {
    try {
        $reader = New-Object System.IO.StreamReader($context.Request.InputStream)
        $body = $reader.ReadToEnd()
        $data = $body | ConvertFrom-Json
        $usuario = $data.usuario
        $clave = $data.clave
        
        Write-Host "Credenciales recibidas - Usuario: $usuario"
        
        $response = "Credenciales recibidas exitosamente."
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    catch {
        $errorResponse = "Error al procesar credenciales: " + $_.Exception.Message
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($errorResponse)
        $context.Response.StatusCode = 500
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    }
    finally {
        if ($context.Response.OutputStream) {
            $context.Response.OutputStream.Close()
        }
    }
}

# Manejo de rutas
while ($listener.IsListening) {
    try {
        $context = $listener.GetContext()
        $path = $context.Request.Url.AbsolutePath
        
        switch ($path) {
            "/subir-archivo" { SubirArchivo $context }
            "/crear-usuario" { CrearUsuario $context }
            "/procesos" { GestionarProcesos $context }
            "/credenciales" { RecibirCredenciales $context }
            "/get-usuarios" { ObtenerUsuarios $context }  
            default {
                $response = "Ruta no encontrada: $path"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
                $context.Response.StatusCode = 404
                $context.Response.ContentLength64 = $buffer.Length
                $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
                $context.Response.OutputStream.Close()
            }
        }

    }
    catch {
        Write-Host "Error en el servidor: " $_.Exception.Message
    }
}

$listener.Stop()