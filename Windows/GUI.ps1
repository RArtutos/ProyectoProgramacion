# MainWindow.ps1
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$httpLinux="192.168.0.2:31111"

$httpLinux = "192.168.0.2"  # Dirección IP del servidor SMB
$sharedFolder = "proyecto"  # Carpeta compartida en el servidor SMB
$username = "proyecto"      # Usuario para autenticarse
$password = "1234"          # Contraseña para autenticarse

$SQLServerBD = "Server=localhost;Database=Proyecto;Integrated Security=True;"


function Crear-Usuario {
    param (
        [string]$Usuario,
        [string]$Nombre,
        [string]$Descripcion,
        [string]$Password
    )

    if (-not $Usuario -or -not $Nombre -or -not $Password) {
        Write-Host "Todos los campos obligatorios deben ser llenados" -ForegroundColor Red
        return
    }

    try {
        # Codificar los parámetros para la URL
        $encodedUsuario = [System.Web.HttpUtility]::UrlEncode($Usuario)
        $encodedPassword = [System.Web.HttpUtility]::UrlEncode($Password)
        $encodedNombre = [System.Web.HttpUtility]::UrlEncode($Nombre)
        $encodedDescripcion = [System.Web.HttpUtility]::UrlEncode($Descripcion)

        # Construir la URL con los parámetros
        $url = "http://192.168.0.2:31111/crear-usuario/datos?username=$encodedUsuario&password=$encodedPassword&fullname=$encodedNombre&description=$encodedDescripcion"

        Write-Host "URL enviada:" -ForegroundColor Cyan
        Write-Host $url -ForegroundColor Yellow

        # Crear el comando de curl con --http0.9
        $curlCommand = @(
            "curl.exe",
            "--http0.9",  # Usar HTTP 0.9
            $url  # La URL con los parámetros
        )

        # Ejecutar el comando curl y mostrar la salida
        Write-Host "Enviando solicitud al servidor..." -ForegroundColor Cyan
        & curl.exe @($curlCommand) 2>&1 | ForEach-Object { Write-Host $_ }

        # Crear el usuario localmente en el sistema
        Write-Host "Creando usuario local: $Usuario" -ForegroundColor Cyan
        New-LocalUser -Name $Usuario -Password (ConvertTo-SecureString -AsPlainText $Password -Force) -FullName $Nombre -Description $Descripcion
        Write-Host "Usuario local creado con éxito." -ForegroundColor Green

    } catch {
        Write-Host "Error al enviar la solicitud HTTP o crear el usuario localmente: $_" -ForegroundColor Red
    }
}



















# Función para exportar la clave en formato PEM
function Export-PemKey {
    param (
        [Parameter(Mandatory=$true)]
        [string]$key,
        
        [Parameter(Mandatory=$true)]
        [string]$keyType
    )

    # Convertir la clave a un byte array
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key)

    # Codificar la clave en Base64
    $base64Key = [Convert]::ToBase64String($keyBytes)
    $pemKey = "-----BEGIN $keyType KEY-----`n$base64Key`n-----END $keyType KEY-----"
    return $pemKey
}

# Función principal para generar llaves
function Generar-Llaves {
    param($usuario)

    # Verificar si la tabla "UsuariosLLaves" existe, si no, crearla
    if (-not (Comprobar-Tabla)) {
        Crear-Tabla
    }

    # Verificar si el usuario ya tiene llaves generadas en SQL Server
    $consulta = "SELECT COUNT(*) FROM UsuariosLLaves WHERE Usuario = '$usuario'"
    $comando = New-Object System.Data.SqlClient.SqlCommand
    $comando.CommandText = $consulta
    $comando.Connection = New-Object System.Data.SqlClient.SqlConnection($SQLServerBD)

    $comando.Connection.Open()
    $resultado = $comando.ExecuteScalar()
    $comando.Connection.Close()

    if ($resultado -gt 0) {
        Write-Host "El usuario ya tiene llaves generadas."
        return $false
    }

# Crear un objeto RSA con un tamaño de clave de 2048 bits
$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)

# Exportar la clave privada en formato PKCS#8
$privateKeyBytes = $rsa.ExportCspBlob($true)
$privateKeyBase64 = [Convert]::ToBase64String($privateKeyBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
$privateKeyPem = "-----BEGIN PRIVATE KEY-----`n$privateKeyBase64`n-----END PRIVATE KEY-----"

# Exportar la clave pública en formato SPKI
$publicKeyBytes = $rsa.ExportCspBlob($false)
$publicKeyBase64 = [Convert]::ToBase64String($publicKeyBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
$publicKeyPem = "-----BEGIN PUBLIC KEY-----`n$publicKeyBase64`n-----END PUBLIC KEY-----"

# Guardar las claves en archivos
$privateKeyPem | Out-File -FilePath "private.pem" -Encoding ASCII
$publicKeyPem | Out-File -FilePath "public.pem" -Encoding ASCII

# Mostrar las claves
Write-Host "Clave Privada (private.pem):"
Write-Host $privateKeyPem
Write-Host "`nClave Pública (public.pem):"
Write-Host $publicKeyPem

Write-Host "`nLas claves han sido guardadas en private.pem y public.pem"


    # Guardar las llaves en SQL Server
    $insertQuery = "INSERT INTO UsuariosLLaves (Usuario, LlavePublica, LlavePrivada) VALUES ('$usuario', '$publicKeyPem', '$privateKeyPem')"
    $comando.CommandText = $insertQuery
    $comando.Connection.Open()
    $comando.ExecuteNonQuery()
    $comando.Connection.Close()

    return $true
}






function Encriptar-Archivo {
    param (
        [string]$archivo,
        [string]$publicKey,
        [string]$usuarioSeleccionado
    )
    
    # Obtener el directorio actual de trabajo
    $currentDir = Get-Location

    # Directorio de salida
    $outputDir = "$currentDir\ArchivosEncriptados"
    if (-not (Test-Path -Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir | Out-Null
    }

    # Limpiar la clave pública: eliminar las cabeceras y saltos de línea "\n" (convertir a saltos de línea reales)
    $publicKeyClean = $publicKey -replace '-----BEGIN PUBLIC KEY-----', '' -replace '-----END PUBLIC KEY-----', '' -replace '\\n', "`r`n"

    # Lógica de encriptación
    try {
        # Leer el contenido del archivo
        $contenido = Get-Content -Path $archivo -Raw
        $contenidoBytes = [System.Text.Encoding]::UTF8.GetBytes($contenido)

        # Definir el archivo de salida encriptado
        $archivoNombre = [System.IO.Path]::GetFileNameWithoutExtension($archivo)
        $extension = [System.IO.Path]::GetExtension($archivo)
        
        # Agregar el nombre del usuario al archivo encriptado
        $archivoEncriptado = Join-Path -Path $outputDir -ChildPath "${archivoNombre}_${usuarioSeleccionado}.enc"

        # Guardar la clave pública en un archivo temporal en el directorio actual
        $publicKeyPath = "$currentDir\publicKey.pem"

        # Formatear la clave pública con las cabeceras adecuadas y guardarla
        $formattedPublicKey = "-----BEGIN PUBLIC KEY-----$publicKeyClean-----END PUBLIC KEY-----"
        Set-Content -Path $publicKeyPath -Value $formattedPublicKey
        $formattedPublicKey | Out-File -FilePath "./key.pem"
        (Get-Content .\key.pem -Raw) | Set-Content -NoNewline .\key.pem

        Write-Host "Encriptando el archivo: $archivo"
        
        # Ejecutar OpenSSL para encriptar el archivo con pkeyutl
        $opensslCmd = "openssl pkeyutl -encrypt -pubin -inkey ./key.pem -in `"$archivo`" -out `"$archivoEncriptado`""
        
        # Ejecutar el comando OpenSSL
        Invoke-Expression $opensslCmd

        # Limpiar el archivo temporal de clave pública
        Remove-Item -Path $publicKeyPath

        Write-Host "Archivo encriptado guardado como: $archivoEncriptado"
        Remove-Item -Path .\key.pem -Force
        return $true
    } catch {
        Write-Host "Error al encriptar el archivo: $_"
        return $false
    }
}













function Desencriptar-Archivo {
    param (
        [string]$archivo,
        [string]$privateKey
    )
    
    try {
        # Crear directorio para archivos desencriptados si no existe
        $outputDir = ".\ArchivosDesencriptados"
        if (-not (Test-Path -Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir | Out-Null
        }

        # Obtener el nombre del archivo y la extensión original
        $archivoNombre = [System.IO.Path]::GetFileNameWithoutExtension($archivo)
        $archivoExtension = [System.IO.Path]::GetExtension($archivo)

        # Remover cualquier sufijo como "_nuevoDef" si está presente
        $archivoNombre = $archivoNombre -replace "_nuevoDef$", ""

        # Obtener la extensión original que va después del primer punto y antes del "_"
        if ($archivoNombre -match "\.(.*?)_") {
            $extensionOriginal = $matches[1]
        } else {
            $extensionOriginal = "txt"  # En caso de que no se encuentre el patrón esperado
        }

        # Asegurarse de que la extensión ".enc" se elimine si está presente
        if ($archivoExtension -eq ".enc") {
            $archivoNombre = [System.IO.Path]::GetFileNameWithoutExtension($archivoNombre) # Remover la extensión ".enc"
            $archivoExtension = "" # Eliminar la extensión ".enc"
        }

        # Definir el archivo de salida sin la extensión ".enc"
        $archivoDesencriptado = Join-Path -Path $outputDir -ChildPath "$archivoNombre.$extensionOriginal"

        # Formatear la llave privada (asegurándonos que tenga el formato adecuado)
        $formattedPrivateKey = "$privateKey"

        # Asegurarse de que no haya duplicados de BEGIN y END en la llave privada
        if ($formattedPrivateKey -match "-----BEGIN PRIVATE KEY-----.*-----END PRIVATE KEY-----") {
            $formattedPrivateKey = $formattedPrivateKey -replace "-----BEGIN PRIVATE KEY-----", ""
            $formattedPrivateKey = $formattedPrivateKey -replace "-----END PRIVATE KEY-----", ""
            $formattedPrivateKey = "-----BEGIN PRIVATE KEY-----`n$formattedPrivateKey`n-----END PRIVATE KEY-----"
        }

        # Guardar llave privada formateada temporalmente
        $privateKeyPath = ".\private_temp.pem"
        $formattedPrivateKey | Out-File -FilePath $privateKeyPath -Force

        # Asegurarse de que no haya saltos de línea extra al final del archivo
        (Get-Content $privateKeyPath -Raw) | Set-Content -NoNewline $privateKeyPath

        # Verificar si el archivo de la llave privada fue creado correctamente
        if (-not (Test-Path -Path $privateKeyPath)) {
            Write-Host "Error: No se pudo crear el archivo de llave privada"
            return $false
        }

        # Verificar el contenido de la llave privada
        $privateKeyContent = Get-Content $privateKeyPath -Raw
        Write-Host "Contenido de la llave privada:"
        Write-Host $privateKeyContent

        # Desencriptar usando OpenSSL
        $opensslCmd = "openssl pkeyutl -decrypt -inkey `"$privateKeyPath`" -in `"$archivo`" -out `"$archivoDesencriptado`"" 
        Write-Host "Ejecutando comando OpenSSL: $opensslCmd"
        Invoke-Expression $opensslCmd

        # Limpiar archivo temporal
        Remove-Item -Path $privateKeyPath -Force

        Write-Host "Archivo desencriptado guardado como: $archivoDesencriptado"
        return $true
    }
    catch {
        Write-Host "Error al desencriptar el archivo: $_"
        return $false
    }
}










function Firmar-Archivo {
    param (
        [string]$archivo,
        [string]$privateKey,
        [string]$usuario
    )
    
    try {
        # Crear directorio para archivos firmados si no existe
        $outputDir = ".\ArchivosFirmados"
        if (-not (Test-Path -Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir | Out-Null
        }

        # Obtener el nombre del archivo y la extensión original
        $archivoNombre = [System.IO.Path]::GetFileName($archivo)
        $archivoExtension = [System.IO.Path]::GetExtension($archivo)

        # Agregar el nombre del usuario al archivo firmado
        $archivoNombreConUsuario = $archivoNombre -replace $archivoExtension, "_$usuario$archivoExtension"

        # Definir el archivo de salida con la extensión .sign
        $archivoFirmado = Join-Path -Path $outputDir -ChildPath "${archivoNombreConUsuario}.sign"

        # Formatear la llave privada (asegurándonos que tenga el formato adecuado)
        $formattedPrivateKey = "$privateKey"

        # Asegurarse de que no haya duplicados de BEGIN y END en la llave privada
        if ($formattedPrivateKey -match "-----BEGIN PRIVATE KEY-----.*-----END PRIVATE KEY-----") {
            $formattedPrivateKey = $formattedPrivateKey -replace "-----BEGIN PRIVATE KEY-----", ""
            $formattedPrivateKey = $formattedPrivateKey -replace "-----END PRIVATE KEY-----", ""
            $formattedPrivateKey = "-----BEGIN PRIVATE KEY-----`n$formattedPrivateKey`n-----END PRIVATE KEY-----"
        }

        # Guardar llave privada formateada temporalmente
        $privateKeyPath = ".\private_temp.pem"
        $formattedPrivateKey | Out-File -FilePath $privateKeyPath -Force

        # Asegurarse de que no haya saltos de línea extra al final del archivo
        (Get-Content $privateKeyPath -Raw) | Set-Content -NoNewline $privateKeyPath

        # Verificar si el archivo de la llave privada fue creado correctamente
        if (-not (Test-Path -Path $privateKeyPath)) {
            Write-Host "Error: No se pudo crear el archivo de llave privada"
            return $false
        }

        # Firmar el archivo usando OpenSSL
        $opensslCmd = "openssl dgst -sha256 -sign `"$privateKeyPath`" -out `"$archivoFirmado`" `"$archivo`""
        Write-Host "Ejecutando comando OpenSSL: $opensslCmd"
        Invoke-Expression $opensslCmd

        # Copiar el archivo original a la carpeta de archivos firmados con el nombre del usuario
        $archivoOriginalDestino = Join-Path -Path $outputDir -ChildPath $archivoNombre
        Copy-Item -Path $archivo -Destination $archivoOriginalDestino

        # Limpiar archivo temporal
        Remove-Item -Path $privateKeyPath -Force

        Write-Host "Archivo firmado guardado como: $archivoFirmado"
        Write-Host "Archivo original copiado como: $archivoOriginalDestino"
        return $true
    }
    catch {
        Write-Host "Error al firmar el archivo: $_"
        return $false
    }
}










function Verificar-Firma {
    param (
        [string]$archivo,
        [string]$firma,
        [string]$publicKey
    )

    try {
        # Guardar la llave pública temporalmente
        $publicKeyPath = ".\public_temp.pem"
        $publicKey | Out-File -FilePath $publicKeyPath

        # Eliminar saltos de línea adicionales en la clave pública
        (Get-Content $publicKeyPath -Raw) | Set-Content -NoNewline $publicKeyPath

        # Verificar la firma usando OpenSSL
        $opensslCmd = "openssl dgst -sha256 -verify $publicKeyPath -signature `"$firma`" `"$archivo`""
        $resultado = Invoke-Expression $opensslCmd

        # Limpiar archivo temporal
        Remove-Item -Path $publicKeyPath -Force

        if ($resultado -match "OK") {
            Write-Host "La firma es válida"
            return $true
        }
        else {
            Write-Host "La firma no es válida"
            return $false
        }
    }
    catch {
        Write-Host "Error al verificar la firma: $_"
        return $false
    }
}



















#Comprobar si ya existe el usuario
function Comprobar-UsuarioExistente {
    param ($usuario)
    $usuarioExistente = Get-LocalUser -Name $usuario -ErrorAction SilentlyContinue
    return $usuarioExistente -ne $null
}





function Comprobar-Tabla {
    # Comprobar si la tabla "UsuariosLLaves" existe
    $consulta = "SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'UsuariosLLaves'"
    $comando = New-Object System.Data.SqlClient.SqlCommand
    $comando.CommandText = $consulta
    $comando.Connection = New-Object System.Data.SqlClient.SqlConnection($SQLServerBD)

    $comando.Connection.Open()
    $resultado = $comando.ExecuteScalar()
    $comando.Connection.Close()

    return $resultado -eq 1
}

function Crear-Tabla {
    # Crear la tabla "UsuariosLLaves" si no existe
    $crearTablaQuery = @"
    CREATE TABLE UsuariosLLaves (
        Usuario NVARCHAR(100) PRIMARY KEY,
        LlavePublica NVARCHAR(MAX),
        LlavePrivada NVARCHAR(MAX)
    );
"@
    $comando = New-Object System.Data.SqlClient.SqlCommand
    $comando.CommandText = $crearTablaQuery
    $comando.Connection = New-Object System.Data.SqlClient.SqlConnection($SQLServerBD)

    $comando.Connection.Open()
    $comando.ExecuteNonQuery()
    $comando.Connection.Close()
}





function Mostrar-CrearUsuario {
    $formUsuario = New-Object System.Windows.Forms.Form
    $formUsuario.Text = "Crear Usuario"
    $formUsuario.Size = New-Object System.Drawing.Size(350,350)
    $formUsuario.StartPosition = "CenterScreen"

    $formImg = new-object System.Windows.Forms.PictureBox
    $formImg.Location = New-Object System.Drawing.Point(10, 0)
    $formImg.size = New-Object System.Drawing.Size(64, 64)
    #$formImg.Image = [System.Drawing.Image]::FromFile("C:\ruta\al\user_icon.png")
    $formImg.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
    $formUsuario.Controls.Add($formImg)

    $lblTitulo = New-Object System.Windows.Forms.Label
    $lblTitulo.Font = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Bold)
    $lblTitulo.Location = New-Object System.Drawing.Point(100, 30)
    $lblTitulo.Size = New-Object System.Drawing.Size(350,20)
    $lblTitulo.Text = "Creación de usuarios"
    $formUsuario.Controls.Add($lblTitulo)

    $lblUsuario = New-Object System.Windows.Forms.Label
    $lblUsuario.Location = New-Object System.Drawing.Point(22,80)
    $lblUsuario.Size = New-Object System.Drawing.Size(75,20)
    $lblUsuario.Text = "Usuario:"
    $formUsuario.Controls.Add($lblUsuario)

    $txtUsuario = New-Object System.Windows.Forms.TextBox
    $txtUsuario.Location = New-Object System.Drawing.Point(105,80)
    $txtUsuario.Size = New-Object System.Drawing.Size(150,20)
    $formUsuario.Controls.Add($txtUsuario)

    $lblNombre = New-Object System.Windows.Forms.Label
    $lblNombre.Location = New-Object System.Drawing.Point(22,120)
    $lblNombre.Size = New-Object System.Drawing.Size(75,40)
    $lblNombre.Text = "Nombre:"
    $formUsuario.Controls.Add($lblNombre)

    $txtNombre = New-Object System.Windows.Forms.TextBox
    $txtNombre.Location = New-Object System.Drawing.Point(105,120)
    $txtNombre.Size = New-Object System.Drawing.Size(150,40)
    $formUsuario.Controls.Add($txtNombre)

    $lblDesc = New-Object System.Windows.Forms.Label
    $lblDesc.Location = New-Object System.Drawing.Point(22,160)
    $lblDesc.Size = New-Object System.Drawing.Size(75,40)
    $lblDesc.Text = "Descripción:"
    $formUsuario.Controls.Add($lblDesc)

    $txtDesc = New-Object System.Windows.Forms.TextBox
    $txtDesc.Location = New-Object System.Drawing.Point(105,160)
    $txtDesc.Size = New-Object System.Drawing.Size(150,40)
    $formUsuario.Controls.Add($txtDesc)

    $lblPasswd = New-Object System.Windows.Forms.Label
    $lblPasswd.Location = New-Object System.Drawing.Point(22,200)
    $lblPasswd.Size = New-Object System.Drawing.Size(75,40)
    $lblPasswd.Text = "Contraseña:"
    $formUsuario.Controls.Add($lblPasswd)

    $txtPasswd = New-Object System.Windows.Forms.TextBox
    $txtPasswd.Location = New-Object System.Drawing.Point(105,200)
    $txtPasswd.Size = New-Object System.Drawing.Size(150,40)
    $txtPasswd.PasswordChar = '*'
    $formUsuario.Controls.Add($txtPasswd)

    $btnCrear = New-Object System.Windows.Forms.Button
    $btnCrear.Location = New-Object System.Drawing.Point(105,240)
    $btnCrear.Size = New-Object System.Drawing.Size(75,23)
    $btnCrear.Text = "Crear"
    $btnCrear.Add_Click({
        $usuario = $txtUsuario.Text
        $nombre = $txtNombre.Text
        $desc = $txtDesc.Text
        $contra = $txtPasswd.Text
        if (-not $usuario -or -not $nombre -or -not $contra) {
          [System.Windows.Forms.MessageBox]::Show("Todos los campos son obligatorios.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        } elseif (Comprobar-UsuarioExistente $usuario) {
          [System.Windows.Forms.MessageBox]::Show("Ya existe un usuario con ese nombre.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        } else {
          Crear-Usuario $usuario $nombre $desc $contra
          [System.Windows.Forms.MessageBox]::Show("Usuario creado exitosamente")
          $formUsuario.Close()
        }
    })
    $formUsuario.Controls.Add($btnCrear)

    $formUsuario.ShowDialog()
}

function Mostrar-GenerarLlaves {
    # Crear la interfaz gráfica
    $formLlaves = New-Object System.Windows.Forms.Form
    $formLlaves.Text = "Generar Llaves"
    $formLlaves.Size = New-Object System.Drawing.Size(300,200)
    $formLlaves.StartPosition = "CenterScreen"

    # Etiqueta para el campo de usuario
    $lblUsuario = New-Object System.Windows.Forms.Label
    $lblUsuario.Location = New-Object System.Drawing.Point(10,20)
    $lblUsuario.Size = New-Object System.Drawing.Size(100,20)
    $lblUsuario.Text = "Usuario:"
    $formLlaves.Controls.Add($lblUsuario)

    # ComboBox para seleccionar el usuario
    $CBUsuario = New-Object System.Windows.Forms.ComboBox
    $CBUsuario.Location = New-Object System.Drawing.Point(110, 20)
    $CBUsuario.Size = New-Object System.Drawing.Size(150, 20)
    $formLlaves.Controls.Add($CBUsuario)

    # Obtener los usuarios locales del sistema
    $usuariosLocales = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" | Select-Object -ExpandProperty Name

    if ($usuariosLocales.Count -eq 0) {
        $CBUsuario.Items.Add("No hay usuarios locales")
        $CBUsuario.SelectedIndex = 0
        $CBUsuario.Enabled = $false
    } else {
        foreach ($usuario in $usuariosLocales) {
            $CBUsuario.Items.Add($usuario)
        }
        $CBUsuario.SelectedIndex = 0
        $CBUsuario.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    }

    # Botón para generar las llaves
    $btnGenerar = New-Object System.Windows.Forms.Button
    $btnGenerar.Location = New-Object System.Drawing.Point(110,60)
    $btnGenerar.Size = New-Object System.Drawing.Size(75,23)
    $btnGenerar.Text = "Generar"
    $formLlaves.Controls.Add($btnGenerar)

    # Acción del botón de generar
    $btnGenerar.Add_Click({
        $usuario = $CBUsuario.SelectedItem
        if (-not $usuario) {
            [System.Windows.Forms.MessageBox]::Show("Por favor seleccione un usuario", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        } else {
            if (Generar-Llaves $usuario) {
                [System.Windows.Forms.MessageBox]::Show("Llaves generadas exitosamente")
                $formLlaves.Close()
            } else {
                [System.Windows.Forms.MessageBox]::Show("El usuario ya tiene llaves generadas.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    })

    # Mostrar el formulario
    $formLlaves.ShowDialog()
}



function Mostrar-SubirArchivo {
    $formArchivo = New-Object System.Windows.Forms.Form
    $formArchivo.Text = "Subir Archivo"
    $formArchivo.Size = New-Object System.Drawing.Size(400,200)
    $formArchivo.StartPosition = "CenterScreen"

    # Definir la ruta inicial como la ubicación donde se ejecuta el script
    $scriptDirectory = Get-Location

    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.InitialDirectory = $scriptDirectory.Path
    $openFileDialog.Filter = "Todos los archivos (*.*)|*.*"

    $lblArchivo = New-Object System.Windows.Forms.Label
    $lblArchivo.Location = New-Object System.Drawing.Point(10,20)
    $lblArchivo.Size = New-Object System.Drawing.Size(100,20)
    $lblArchivo.Text = "Archivo:"
    $formArchivo.Controls.Add($lblArchivo)

    $txtArchivo = New-Object System.Windows.Forms.TextBox
    $txtArchivo.Location = New-Object System.Drawing.Point(110,20)
    $txtArchivo.Size = New-Object System.Drawing.Size(200,20)
    $txtArchivo.ReadOnly = $true
    $formArchivo.Controls.Add($txtArchivo)

    $btnExaminar = New-Object System.Windows.Forms.Button
    $btnExaminar.Location = New-Object System.Drawing.Point(320,20)
    $btnExaminar.Size = New-Object System.Drawing.Size(60,23)
    $btnExaminar.Text = "..."
    $btnExaminar.Add_Click({
        if ($openFileDialog.ShowDialog() -eq 'OK') {
            $txtArchivo.Text = $openFileDialog.FileName
        }
    })
    $formArchivo.Controls.Add($btnExaminar)

    $btnSubir = New-Object System.Windows.Forms.Button
    $btnSubir.Location = New-Object System.Drawing.Point(110,60)
    $btnSubir.Size = New-Object System.Drawing.Size(75,23)
    $btnSubir.Text = "Subir"
    $btnSubir.Add_Click({
    if ($txtArchivo.Text) {
        $filePath = $txtArchivo.Text
        $fileName = [System.IO.Path]::GetFileName($filePath)

# Ruta al recurso compartido SMB
$destinationPath = "\\192.168.0.2\proyecto\$fileName"  # Ruta al recurso compartido

# Usar las credenciales directamente
$usuario = "proyecto"
$contraseña = "1234"

# Convertir la contraseña a un objeto SecureString
$securePassword = ConvertTo-SecureString $contraseña -AsPlainText -Force

# Crear las credenciales
$credentials = New-Object System.Management.Automation.PSCredential($usuario, $securePassword)

# Mapear el recurso compartido con New-PSDrive usando una letra de unidad
New-PSDrive -Name "Z" -PSProvider FileSystem -Root "\\192.168.0.2\proyecto" -Credential $credentials

# Copiar el archivo al servidor SMB
Copy-Item -Path $filePath -Destination "Z:\$fileName"

# Mostrar mensaje de éxito
[System.Windows.Forms.MessageBox]::Show("Archivo copiado exitosamente")

# Opcional: Desmontar la unidad de red después de usarla
Remove-PSDrive -Name "Z"

        # Ejecutar el comando smbclient
        Invoke-Expression $smbCommand

        # Mostrar mensaje de éxito
        [System.Windows.Forms.MessageBox]::Show("Archivo subido exitosamente")
        $formArchivo.Close()
    } else {
        [System.Windows.Forms.MessageBox]::Show("Por favor seleccione un archivo")
    }
})

$formArchivo.Controls.Add($btnSubir)

$formArchivo.ShowDialog()
}



function Mostrar-EncriptarArchivo {
    $formEncriptar = New-Object System.Windows.Forms.Form
    $formEncriptar.Text = "Encriptar Archivo"
    $formEncriptar.Size = New-Object System.Drawing.Size(400,250)
    $formEncriptar.StartPosition = "CenterScreen"

    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Todos los archivos (*.*)|*.*"

    # File Selection
    $lblArchivo = New-Object System.Windows.Forms.Label
    $lblArchivo.Location = New-Object System.Drawing.Point(10,20)
    $lblArchivo.Size = New-Object System.Drawing.Size(100,20)
    $lblArchivo.Text = "Archivo:"
    $formEncriptar.Controls.Add($lblArchivo)

    $txtArchivo = New-Object System.Windows.Forms.TextBox
    $txtArchivo.Location = New-Object System.Drawing.Point(110,20)
    $txtArchivo.Size = New-Object System.Drawing.Size(200,20)
    $txtArchivo.ReadOnly = $true
    $formEncriptar.Controls.Add($txtArchivo)

    $btnExaminar = New-Object System.Windows.Forms.Button
    $btnExaminar.Location = New-Object System.Drawing.Point(320,20)
    $btnExaminar.Size = New-Object System.Drawing.Size(60,23)
    $btnExaminar.Text = "..."
    $btnExaminar.Add_Click({
        if ($openFileDialog.ShowDialog() -eq 'OK') {
            $txtArchivo.Text = $openFileDialog.FileName
        }
    })
    $formEncriptar.Controls.Add($btnExaminar)

    # User Selection
    $lblUsuario = New-Object System.Windows.Forms.Label
    $lblUsuario.Location = New-Object System.Drawing.Point(10,60)
    $lblUsuario.Size = New-Object System.Drawing.Size(100,20)
    $lblUsuario.Text = "Usuario:"
    $formEncriptar.Controls.Add($lblUsuario)

    $CBUsuario = New-Object System.Windows.Forms.ComboBox
    $CBUsuario.Location = New-Object System.Drawing.Point(110, 60)
    $CBUsuario.Size = New-Object System.Drawing.Size(150, 20)
    $formEncriptar.Controls.Add($CBUsuario)

    # Llenar la lista de usuarios con la información del servicio
    try {
        # Realizar la solicitud para obtener la lista de usuarios
        $response = curl.exe "http://192.168.0.2:31111/get-usuarios" --http0.9 | Select-Object -Skip 6

        Write-Host "Respuesta cruda del servidor: $response"  # Depuración

        # Eliminar la parte que contiene "[DEBUG] MÃ©todo: GET, Ruta: get-usuarios"
        # Usar una expresión regular para eliminar el texto [DEBUG] hasta el final de la cadena
        $cleanedResponse = $response -replace "\[DEBUG\].*?(\{.*\})", '$1'

        # Verificar si la respuesta limpia es JSON válido
        $isValidJson = $false
        try {
            $jsonData = $cleanedResponse | ConvertFrom-Json
            $isValidJson = $true
        } catch {
            Write-Host "Error al convertir la respuesta a JSON: $_"
        }

        if ($isValidJson) {
            if ($jsonData.Count -eq 0) {
                $CBUsuario.Items.Add("No hay usuarios disponibles")
                $CBUsuario.SelectedIndex = 0
                $CBUsuario.Enabled = $false
            } else {
                # Almacenar la lista completa de usuarios y claves públicas
                $usuarios = @{}

                foreach ($usuario in $jsonData) {
                    $CBUsuario.Items.Add($usuario.usuario)
                    $usuarios[$usuario.usuario] = $usuario.llave_publica
                }

                $CBUsuario.SelectedIndex = 0
                $CBUsuario.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
            }
        } else {
            Write-Host "Error: No se pudo obtener un JSON válido"
            $CBUsuario.Items.Add("Error al obtener usuarios")
            $CBUsuario.SelectedIndex = 0
            $CBUsuario.Enabled = $false
        }
    } catch {
        Write-Host "Error al obtener usuarios: $_"
        $CBUsuario.Items.Add("Error al obtener usuarios")
        $CBUsuario.SelectedIndex = 0
        $CBUsuario.Enabled = $false
    }

    # Encrypt Button
    $btnEncriptar = New-Object System.Windows.Forms.Button
    $btnEncriptar.Location = New-Object System.Drawing.Point(110,100)
    $btnEncriptar.Size = New-Object System.Drawing.Size(75,23)
    $btnEncriptar.Text = "Encriptar"
    $btnEncriptar.Add_Click({
        if ($txtArchivo.Text.Trim() -and $CBUsuario.SelectedItem -and $CBUsuario.SelectedItem -ne "No hay usuarios disponibles") {
            $usuarioSeleccionado = $CBUsuario.SelectedItem

            # Obtener la clave pública directamente de la lista de usuarios
            $publicKey = $usuarios[$usuarioSeleccionado]

            if (Encriptar-Archivo $txtArchivo.Text $publicKey $usuarioSeleccionado) {
                [System.Windows.Forms.MessageBox]::Show("Archivo encriptado exitosamente")
                $formEncriptar.Close()
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Por favor complete todos los campos o seleccione un usuario válido")
        }
    })
    $formEncriptar.Controls.Add($btnEncriptar)

    $formEncriptar.ShowDialog()
}








# Variable para almacenar el formulario de procesos
$formProcesos = $null

# Función para mostrar la lista de procesos
function Mostrar-ListaProcesos {
    # Si el formulario ya está abierto, solo enfócalo
    if ($formProcesos -and !$formProcesos.IsDisposed) {
        $formProcesos.Activate()
        return
    }

    # Crear un nuevo formulario
    $formProcesos = New-Object System.Windows.Forms.Form
    $formProcesos.Text = "Lista de Procesos"
    $formProcesos.Size = New-Object System.Drawing.Size(600, 400)

    # Crear un ListBox para mostrar los procesos
    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Size = New-Object System.Drawing.Size(500, 200)
    $listBox.Location = New-Object System.Drawing.Point(50, 50)

    # Crear un botón de "Refrescar"
    $btnRefresh = New-Object System.Windows.Forms.Button
    $btnRefresh.Text = "Refrescar"
    $btnRefresh.Size = New-Object System.Drawing.Size(100, 30)
    $btnRefresh.Location = New-Object System.Drawing.Point(50, 270)
    
    $response = curl.exe -"http://192.168.0.2:31111/procesos?accion=listar" --http0.9
    $content = $response -split "\n" | Where-Object { $_ -match "PID," }
    $processList = $content -replace "PID,", "" -split " "
    $listBox.Items.Clear()
    foreach ($process in $processList) {
        $listBox.Items.Add($process.ToString())
    }
    
    $btnRefresh.Add_Click({
        # Actualizar la lista de procesos
        $response = curl.exe "http://192.168.0.2:31111/procesos?accion=listar" --http0.9
        $content = $response -split "\n" | Where-Object { $_ -match "PID," }
        $processList = $content -replace "PID,", "" -split " "
        $listBox.Items.Clear()
        foreach ($process in $processList) {
            $listBox.Items.Add($process.ToString())
        }
    })

    # Crear un botón de "Detener"
    $btnStop = New-Object System.Windows.Forms.Button
    $btnStop.Text = "Detener Proceso"
    $btnStop.Size = New-Object System.Drawing.Size(100, 30)
    $btnStop.Location = New-Object System.Drawing.Point(160, 270)
    $btnStop.Add_Click({
        $selectedProcess = $listBox.SelectedItem
        if ($selectedProcess) {
            # Extraer el PID del proceso seleccionado
            $npid = ($selectedProcess.Split(",")[0]).Trim()
            # Mostrar el PID en la terminal
            Write-Host "PID seleccionado: $npid"
            # Ejecutar el comando para detener el proceso
            curl.exe "http://192.168.0.2:31111/procesos?accion=detener&pid=$npid" --http0.9
        } else {
            Write-Host "No se seleccionó ningún proceso."
        }
    })

    # Añadir controles al formulario
    $formProcesos.Controls.Add($listBox)
    $formProcesos.Controls.Add($btnRefresh)
    $formProcesos.Controls.Add($btnStop)

    # Mostrar el formulario
    $formProcesos.ShowDialog()
}



function Mostrar-DesencriptarArchivo {
    $formEncriptar = New-Object System.Windows.Forms.Form
    $formEncriptar.Text = "Desencriptar Archivo"
    $formEncriptar.Size = New-Object System.Drawing.Size(400,250)
    $formEncriptar.StartPosition = "CenterScreen"

    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Todos los archivos (*.*)|*.*"

    # File Selection
    $lblArchivo = New-Object System.Windows.Forms.Label
    $lblArchivo.Location = New-Object System.Drawing.Point(10,20)
    $lblArchivo.Size = New-Object System.Drawing.Size(100,20)
    $lblArchivo.Text = "Archivo:"
    $formEncriptar.Controls.Add($lblArchivo)

    $txtArchivo = New-Object System.Windows.Forms.TextBox
    $txtArchivo.Location = New-Object System.Drawing.Point(110,20)
    $txtArchivo.Size = New-Object System.Drawing.Size(200,20)
    $txtArchivo.ReadOnly = $true
    $formEncriptar.Controls.Add($txtArchivo)

    $btnExaminar = New-Object System.Windows.Forms.Button
    $btnExaminar.Location = New-Object System.Drawing.Point(320,20)
    $btnExaminar.Size = New-Object System.Drawing.Size(60,23)
    $btnExaminar.Text = "..."
    $btnExaminar.Add_Click({
        if ($openFileDialog.ShowDialog() -eq 'OK') {
            $txtArchivo.Text = $openFileDialog.FileName
        }
    })
    $formEncriptar.Controls.Add($btnExaminar)

    # User Selection
    $lblUsuario = New-Object System.Windows.Forms.Label
    $lblUsuario.Location = New-Object System.Drawing.Point(10,60)
    $lblUsuario.Size = New-Object System.Drawing.Size(100,20)
    $lblUsuario.Text = "Usuario:"
    $formEncriptar.Controls.Add($lblUsuario)

    $CBUsuario = New-Object System.Windows.Forms.ComboBox
    $CBUsuario.Location = New-Object System.Drawing.Point(110, 60)
    $CBUsuario.Size = New-Object System.Drawing.Size(150, 20)
    $formEncriptar.Controls.Add($CBUsuario)

    # Llenar la lista de usuarios con la información del servicio
    try {
    # Crear conexión con la base de datos
    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $SQLServerBD
    $connection.Open()

    # Crear el comando SQL para obtener usuarios y sus claves privadas
    $query = "SELECT usuario, LlavePrivada FROM UsuariosLLaves"
    $command = $connection.CreateCommand()
    $command.CommandText = $query

    # Ejecutar la consulta y leer los datos
    $reader = $command.ExecuteReader()
    $usuarios = @{}

    while ($reader.Read()) {
        # Recuperar el nombre de usuario y la llave privada
        $usuario = $reader["usuario"]
        $llavePrivada = $reader["LlavePrivada"]

        # Almacenar el usuario y su llave privada en el diccionario
        $usuarios[$usuario] = $llavePrivada
        $CBUsuario.Items.Add($usuario)
    }

    # Cerrar el lector y la conexión
    $reader.Close()
    $connection.Close()

    # Si no hay usuarios, deshabilitar el ComboBox
    if ($usuarios.Count -eq 0) {
        $CBUsuario.Items.Add("No hay usuarios disponibles")
        $CBUsuario.SelectedIndex = 0
        $CBUsuario.Enabled = $false
    } else {
        # Si hay usuarios, configurar el ComboBox
        $CBUsuario.SelectedIndex = 0
        $CBUsuario.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    }
} catch {
    Write-Host "Error al obtener usuarios desde SQL Server: $_"
    $CBUsuario.Items.Add("Error al obtener usuarios")
    $CBUsuario.SelectedIndex = 0
    $CBUsuario.Enabled = $false
}

# Desencriptar Button
$btnEncriptar = New-Object System.Windows.Forms.Button
$btnEncriptar.Location = New-Object System.Drawing.Point(110,100)
$btnEncriptar.Size = New-Object System.Drawing.Size(75,23)
$btnEncriptar.Text = "Desencriptar"
$btnEncriptar.Add_Click({
    if ($txtArchivo.Text.Trim() -and $CBUsuario.SelectedItem -and $CBUsuario.SelectedItem -ne "No hay usuarios disponibles") {
        $usuarioSeleccionado = $CBUsuario.SelectedItem

        # Obtener la clave privada directamente de la lista de usuarios
        $privatedKey = $usuarios[$usuarioSeleccionado]

        if (Desencriptar-Archivo $txtArchivo.Text $privatedKey) {
            [System.Windows.Forms.MessageBox]::Show("Archivo desencriptado exitosamente")
            $formEncriptar.Close()
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Por favor complete todos los campos o seleccione un usuario válido")
    }
})
$formEncriptar.Controls.Add($btnEncriptar)

$formEncriptar.ShowDialog()
}


function Mostrar-FirmarArchivo {
    $formFirmar = New-Object System.Windows.Forms.Form
    $formFirmar.Text = "Firmar Archivo"
    $formFirmar.Size = New-Object System.Drawing.Size(400,250)
    $formFirmar.StartPosition = "CenterScreen"

    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Todos los archivos (*.*)|*.*"

    # File Selection
    $lblArchivo = New-Object System.Windows.Forms.Label
    $lblArchivo.Location = New-Object System.Drawing.Point(10,20)
    $lblArchivo.Size = New-Object System.Drawing.Size(100,20)
    $lblArchivo.Text = "Archivo:"
    $formFirmar.Controls.Add($lblArchivo)

    $txtArchivo = New-Object System.Windows.Forms.TextBox
    $txtArchivo.Location = New-Object System.Drawing.Point(110,20)
    $txtArchivo.Size = New-Object System.Drawing.Size(200,20)
    $txtArchivo.ReadOnly = $true
    $formFirmar.Controls.Add($txtArchivo)

    $btnExaminar = New-Object System.Windows.Forms.Button
    $btnExaminar.Location = New-Object System.Drawing.Point(320,20)
    $btnExaminar.Size = New-Object System.Drawing.Size(60,23)
    $btnExaminar.Text = "..."
    $btnExaminar.Add_Click({
        if ($openFileDialog.ShowDialog() -eq 'OK') {
            $txtArchivo.Text = $openFileDialog.FileName
        }
    })
    $formFirmar.Controls.Add($btnExaminar)

    # User Selection
    $lblUsuario = New-Object System.Windows.Forms.Label
    $lblUsuario.Location = New-Object System.Drawing.Point(10,60)
    $lblUsuario.Size = New-Object System.Drawing.Size(100,20)
    $lblUsuario.Text = "Usuario:"
    $formFirmar.Controls.Add($lblUsuario)

    $CBUsuario = New-Object System.Windows.Forms.ComboBox
    $CBUsuario.Location = New-Object System.Drawing.Point(110, 60)
    $CBUsuario.Size = New-Object System.Drawing.Size(150, 20)
    $formFirmar.Controls.Add($CBUsuario)

    # Llenar la lista de usuarios con la información del servicio
    try {
        # Crear conexión con la base de datos
        $connection = New-Object System.Data.SqlClient.SqlConnection
        $connection.ConnectionString = $SQLServerBD
        $connection.Open()

        # Crear el comando SQL para obtener usuarios y sus claves privadas
        $query = "SELECT usuario, LlavePrivada FROM UsuariosLLaves"
        $command = $connection.CreateCommand()
        $command.CommandText = $query

        # Ejecutar la consulta y leer los datos
        $reader = $command.ExecuteReader()
        $usuarios = @{}

        while ($reader.Read()) {
            # Recuperar el nombre de usuario y la llave privada
            $usuario = $reader["usuario"]
            $llavePrivada = $reader["LlavePrivada"]

            # Almacenar el usuario y su llave privada en el diccionario
            $usuarios[$usuario] = $llavePrivada
            $CBUsuario.Items.Add($usuario)
        }

        # Cerrar el lector y la conexión
        $reader.Close()
        $connection.Close()

        # Si no hay usuarios, deshabilitar el ComboBox
        if ($usuarios.Count -eq 0) {
            $CBUsuario.Items.Add("No hay usuarios disponibles")
            $CBUsuario.SelectedIndex = 0
            $CBUsuario.Enabled = $false
        } else {
            # Si hay usuarios, configurar el ComboBox
            $CBUsuario.SelectedIndex = 0
            $CBUsuario.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
        }
    } catch {
        Write-Host "Error al obtener usuarios desde SQL Server: $_"
        $CBUsuario.Items.Add("Error al obtener usuarios")
        $CBUsuario.SelectedIndex = 0
        $CBUsuario.Enabled = $false
    }

    # Firmar Button
    $btnFirmar = New-Object System.Windows.Forms.Button
    $btnFirmar.Location = New-Object System.Drawing.Point(110,100)
    $btnFirmar.Size = New-Object System.Drawing.Size(75,23)
    $btnFirmar.Text = "Firmar"
    $btnFirmar.Add_Click({
        if ($txtArchivo.Text.Trim() -and $CBUsuario.SelectedItem -and $CBUsuario.SelectedItem -ne "No hay usuarios disponibles") {
            $usuarioSeleccionado = $CBUsuario.SelectedItem

            # Obtener la clave privada directamente de la lista de usuarios
            $privadaLlave = $usuarios[$usuarioSeleccionado]

            if (Firmar-Archivo $txtArchivo.Text $privadaLlave $usuarioSeleccionado) {
                [System.Windows.Forms.MessageBox]::Show("Archivo firmado exitosamente")
                $formFirmar.Close()
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Por favor complete todos los campos o seleccione un usuario válido")
        }
    })
    $formFirmar.Controls.Add($btnFirmar)

    $formFirmar.ShowDialog()
}

function Mostrar-VerificarFirma {
    $formVerificar = New-Object System.Windows.Forms.Form
    $formVerificar.Text = "Verificar Firma"
    $formVerificar.Size = New-Object System.Drawing.Size(400,250)
    $formVerificar.StartPosition = "CenterScreen"

    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Todos los archivos (*.*)|*.*"

    # File Selection: Archivo Original
    $lblArchivoOriginal = New-Object System.Windows.Forms.Label
    $lblArchivoOriginal.Location = New-Object System.Drawing.Point(10,20)
    $lblArchivoOriginal.Size = New-Object System.Drawing.Size(100,20)
    $lblArchivoOriginal.Text = "Archivo Original:"
    $formVerificar.Controls.Add($lblArchivoOriginal)

    $txtArchivoOriginal = New-Object System.Windows.Forms.TextBox
    $txtArchivoOriginal.Location = New-Object System.Drawing.Point(110,20)
    $txtArchivoOriginal.Size = New-Object System.Drawing.Size(200,20)
    $txtArchivoOriginal.ReadOnly = $true
    $formVerificar.Controls.Add($txtArchivoOriginal)

    $btnExaminarOriginal = New-Object System.Windows.Forms.Button
    $btnExaminarOriginal.Location = New-Object System.Drawing.Point(320,20)
    $btnExaminarOriginal.Size = New-Object System.Drawing.Size(60,23)
    $btnExaminarOriginal.Text = "..."
    $btnExaminarOriginal.Add_Click({
        if ($openFileDialog.ShowDialog() -eq 'OK') {
            $txtArchivoOriginal.Text = $openFileDialog.FileName
        }
    })
    $formVerificar.Controls.Add($btnExaminarOriginal)

    # File Selection: Archivo Firmado
    $lblArchivoFirmado = New-Object System.Windows.Forms.Label
    $lblArchivoFirmado.Location = New-Object System.Drawing.Point(10,60)
    $lblArchivoFirmado.Size = New-Object System.Drawing.Size(100,20)
    $lblArchivoFirmado.Text = "Archivo Firmado:"
    $formVerificar.Controls.Add($lblArchivoFirmado)

    $txtArchivoFirmado = New-Object System.Windows.Forms.TextBox
    $txtArchivoFirmado.Location = New-Object System.Drawing.Point(110,60)
    $txtArchivoFirmado.Size = New-Object System.Drawing.Size(200,20)
    $txtArchivoFirmado.ReadOnly = $true
    $formVerificar.Controls.Add($txtArchivoFirmado)

    $btnExaminarFirmado = New-Object System.Windows.Forms.Button
    $btnExaminarFirmado.Location = New-Object System.Drawing.Point(320,60)
    $btnExaminarFirmado.Size = New-Object System.Drawing.Size(60,23)
    $btnExaminarFirmado.Text = "..."
    $btnExaminarFirmado.Add_Click({
        if ($openFileDialog.ShowDialog() -eq 'OK') {
            $txtArchivoFirmado.Text = $openFileDialog.FileName
        }
    })
    $formVerificar.Controls.Add($btnExaminarFirmado)

    # User Selection
    $lblUsuario = New-Object System.Windows.Forms.Label
    $lblUsuario.Location = New-Object System.Drawing.Point(10,100)
    $lblUsuario.Size = New-Object System.Drawing.Size(100,20)
    $lblUsuario.Text = "Usuario:"
    $formVerificar.Controls.Add($lblUsuario)

    $CBUsuario = New-Object System.Windows.Forms.ComboBox
    $CBUsuario.Location = New-Object System.Drawing.Point(110, 100)
    $CBUsuario.Size = New-Object System.Drawing.Size(150, 20)
    $formVerificar.Controls.Add($CBUsuario)

    # Llenar la lista de usuarios con la información del servicio
    try {
        # Realizar la solicitud para obtener la lista de usuarios
        $response = curl.exe "http://192.168.0.2:31111/get-usuarios" --http0.9 | Select-Object -Skip 6

        Write-Host "Respuesta cruda del servidor: $response"  # Depuración

        # Eliminar la parte que contiene "[DEBUG] MÃ©todo: GET, Ruta: get-usuarios"
        $cleanedResponse = $response -replace "\[DEBUG\].*?(\{.*\})", '$1'

        # Verificar si la respuesta limpia es JSON válido
        $isValidJson = $false
        try {
            $jsonData = $cleanedResponse | ConvertFrom-Json
            $isValidJson = $true
        } catch {
            Write-Host "Error al convertir la respuesta a JSON: $_"
        }

        if ($isValidJson) {
            if ($jsonData.Count -eq 0) {
                $CBUsuario.Items.Add("No hay usuarios disponibles")
                $CBUsuario.SelectedIndex = 0
                $CBUsuario.Enabled = $false
            } else {
                # Almacenar la lista completa de usuarios y claves públicas
                $usuarios = @{ }

                foreach ($usuario in $jsonData) {
                    $CBUsuario.Items.Add($usuario.usuario)
                    $usuarios[$usuario.usuario] = $usuario.llave_publica
                }

                $CBUsuario.SelectedIndex = 0
                $CBUsuario.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
            }
        } else {
            Write-Host "Error: No se pudo obtener un JSON válido"
            $CBUsuario.Items.Add("Error al obtener usuarios")
            $CBUsuario.SelectedIndex = 0
            $CBUsuario.Enabled = $false
        }
    } catch {
        Write-Host "Error al obtener usuarios: $_"
        $CBUsuario.Items.Add("Error al obtener usuarios")
        $CBUsuario.SelectedIndex = 0
        $CBUsuario.Enabled = $false
    }

    # Verificar Button
    $btnVerificar = New-Object System.Windows.Forms.Button
    $btnVerificar.Location = New-Object System.Drawing.Point(110,140)
    $btnVerificar.Size = New-Object System.Drawing.Size(75,23)
    $btnVerificar.Text = "Verificar"
    $btnVerificar.Add_Click({
        if ($txtArchivoOriginal.Text.Trim() -and $txtArchivoFirmado.Text.Trim() -and $CBUsuario.SelectedItem -and $CBUsuario.SelectedItem -ne "No hay usuarios disponibles") {
            $usuarioSeleccionado = $CBUsuario.SelectedItem

            # Obtener la clave pública directamente de la lista de usuarios
            $publicKey = $usuarios[$usuarioSeleccionado]

            # Aquí agregar la lógica para verificar la firma, usando los archivos y la clave pública
            if (Verificar-Firma $txtArchivoOriginal.Text $txtArchivoFirmado.Text $publicKey) {
                [System.Windows.Forms.MessageBox]::Show("Firma verificada exitosamente")
            } else {
                [System.Windows.Forms.MessageBox]::Show("La firma no es válida")
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Por favor complete todos los campos o seleccione un usuario válido")
        }
    })
    $formVerificar.Controls.Add($btnVerificar)

    $formVerificar.ShowDialog()
}


# Main Form Creation and Setup
$form = New-Object System.Windows.Forms.Form
$form.Text = "Sistema de Archivos Seguro"
$form.Size = New-Object System.Drawing.Size(600,400)
$form.StartPosition = "CenterScreen"

# Main Menu
$menu = New-Object System.Windows.Forms.MenuStrip
$form.MainMenuStrip = $menu

# Users Menu
$menuUsuarios = New-Object System.Windows.Forms.ToolStripMenuItem
$menuUsuarios.Text = "Usuarios"
$menuUsuarios.DropDownItems.Add("Crear Usuario", $null).Add_Click({Mostrar-CrearUsuario})
$menuUsuarios.DropDownItems.Add("Generar Llaves", $null).Add_Click({Mostrar-GenerarLlaves})

# Files Menu
$menuArchivos = New-Object System.Windows.Forms.ToolStripMenuItem
$menuArchivos.Text = "Archivos"
$menuArchivos.DropDownItems.Add("Subir Archivo", $null).Add_Click({Mostrar-SubirArchivo})


# Security Menu
$menuSeguridad = New-Object System.Windows.Forms.ToolStripMenuItem
$menuSeguridad.Text = "Seguridad"
$menuSeguridad.DropDownItems.Add("Encriptar Archivo", $null).Add_Click({Mostrar-EncriptarArchivo})



$menuSeguridad.DropDownItems.Add("Desencriptar Archivo", $null).Add_Click({
    Mostrar-DesencriptarArchivo
})

$menuSeguridad.DropDownItems.Add("Firmar Archivo", $null).Add_Click({
    Mostrar-FirmarArchivo
})

$menuSeguridad.DropDownItems.Add("Verificar Firma", $null).Add_Click({
    Mostrar-VerificarFirma
})

# Processes Menu
$menuProcesos = New-Object System.Windows.Forms.ToolStripMenuItem
$menuProcesos.Text = "Procesos"
$menuProcesos.DropDownItems.Add("Ver Procesos", $null).Add_Click({
    Mostrar-ListaProcesos
})

# Add Menus to MenuStrip
$menu.Items.Add($menuUsuarios)
$menu.Items.Add($menuArchivos)
$menu.Items.Add($menuSeguridad)
$menu.Items.Add($menuProcesos)

# Add MenuStrip to Form
$form.Controls.Add($menu)

# Show Main Form
$form.ShowDialog()