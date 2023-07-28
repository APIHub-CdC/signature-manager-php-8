# Signature-Manager-PHP-8


## Requisitos

- PHP >= 8.1
- Sistema Linux/Unix
- Git

### Dependencias adicionales

Se debe contar con las siguientes dependencias:
- openssl
- Composer [vea como instalar][1]

```sh

# Para RHEL o derivados:
yum install openssl
dnf install openssl

# Para Debian o derivados:
apt install openssl

```
  

## Guía de inicio

### Paso 1. Clonar repositorio
- Clona este repositorio en tu sistema Linux/Unix
- Utiliza el siguiente comando:

```sh
    git clone nombre_del_repositorio
```

### Paso 2. Generar llaves criptográficas

 - Ejecuta el archivo *crypto_keys_generator.sh* desde la línea de comandos de su sistema Unix/Linux
 - Resguardar en una bóveda segura la contraseña elegida para el keystore durante la ejecución del archivo *crypto_keys_generator.sh*
 - Identifica el directorio generado donde se guardaron las llaves generadas

### Paso 3. Descarga el certificado público de Círculo de Crédito

 1. Ingresa al portal de desarrolladores
 2. Inicia sesión en el portal
 3. Descarga el certificado

  

### Paso 4. Agrega el componente de firmado en tu proyecto

Agrega la dependencia de este componente signature-manager-php en tu código PHP a través del administrador de dependencias Composer.

Ejecuta el comando de Composer para instalar la dependencia, dependiendo del caso se tendrá que ejecutar el comando *install* o *update*.

```sh
    composer install
```

### Paso 5. Uso del componente de firmado

Si utilizas en tu proyecto la biblioteca *GuzzleHttp* para realizar las peticiones HTTP puedes ocupar directamente nuestras clases *MiddlewareEvents* y *SignatureService* para inyectar en tu cliente *GuzzleHttp* los handler events que realizan el firmado de todos los HTTP Request POST y GET y verificación de firma del HTTP response.

**IMPORTANTE:**
El certificado cdc (Círculo de Crédito) es otorgado únicamente por Círculo de Crédito a través de su portal de desarrolladores. Este certificado NO es generado por el cliente/otorgante.

```php
    use \GuzzleHttp\Client;
    use \GuzzleHttp\HandlerStack;
    use \Signer\Manager\Interceptor\SignatureService;
    use \Signer\Manager\Interceptor\MiddlewareEvents;
    // ...
    
    // Configure the SignatureService
    $cdcCertificateFile = "/my_path/cdc_certificate.pem";
    $pkcs12File = "/my_path/keystore.p12";
    $pkcs12Password = "my_keystore_secure_password";
    $signatureService = new SignatureService($cdcCertificateFile, $pkcs12File, $pkcs12Password);
    
    // Add the events to the HTTP client
    $events = new MiddlewareEvents($signatureService);
    $handler = HandlerStack::create();
    $handler->push($events->add_signature_header('x-signature'));
    $handler->push($events->verify_signature_header('x-signature'));
    $client = new Client(['handler' => $handler]);
    
    // Now use the HTTP client and it will automatically sign the requests, as well as validate the responses.
    
    // ...
```

### Paso 6. Opcional
Utilice directamente la clase *SignatureService* para generar y validar manualmente la firma digital 'x-signature', o utilice la clase para integrarla en su flujo de desarrollo para un uso personalizado.

[CONDICIONES DE USO, REPRODUCCIÓN Y DISTRIBUCIÓN](https://github.com/APIHub-CdC/licencias-cdc)

[1]: https://getcomposer.org/doc/00-intro.md#installation-linux-unix-macos