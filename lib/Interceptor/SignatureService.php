<?php
/* Copyright (C) 2023 Círculo de Crédito - All Rights Reserved
 * 
 * Unauthorized use, copy, modification and/or distribution 
 * of this software via any medium is strictly prohibited.
 * 
 * This software CAN ONLY be used under the terms and conditions 
 * established by 'Círculo de Crédito' company.
 * 
 * Proprietary software.
 */
namespace Signer\Manager\Interceptor;

use \Signer\Manager\Interceptor\MyLogger;

/**
 * Cryptographic component to generate and validate digital signatures using the following specification:
 * SHA256withECDSA - secp384r
 * 
 * IMPORTANT: Openssl MUST be installed on your system.
 * 
 * @author Gamaliel Lobato
 * @author Ricardo Rubio
 * 
 * @copyright 2020-2023 Círculo de Crédito
 */
Class SignatureService
{
    
    private $privateKey = null;
    private $publicKey  = null;
    private $log        = null;
    
    /**
     * Constructor.
     * 
     * The PCKS12 file contains the private key for signature generation.
     * The public certificate corresponds to the one that was granted by 'Círculo de Crédito'.
     * The public certificate MUST be in PEM format.
     * 
     * @param string $cdcCertificateFile    The full file system path of the public certificate PEM.
     * @param string $pkcs12File            The full file system path of the PCKS12.
     * @param string $pkcs12Password        The password of the PCKS12 file.
     * 
     * @throws InvalidArgumentException If the provided PCKS12 or certificate files are invalid.
     * @throws Exception                If an error occurs during the cryptographic keys loading process.
     */
    public function __construct($cdcCertificateFile = null, $pkcs12File = null, $pkcs12Password = "")
    {
	    $this->log = new MyLogger('SignatureService');

        $this->log->info("Starting signature manager process ...");

        if($pkcs12File == null || empty($pkcs12File)){
            $this->log->error("The PKCS12 file path is empty!");

            throw new InvalidArgumentException("The path of the PKCS12 file was not specified.");
        }

        if($cdcCertificateFile == null || empty($cdcCertificateFile)){
            $this->log->error("The public Certificate file path is empty!");

            throw new InvalidArgumentException(
                "The path of the 'Círculo de Crédito' public certificate file was not specified.");
        }

        if (!file_exists($pkcs12File)) {
            $this->log->error("The specified PKCS12 file: {$pkcs12File} does not exist.");

            throw new InvalidArgumentException("The specified PKCS12 file: {$pkcs12File} does not exist."); 
        }
        
        if (!file_exists($cdcCertificateFile)) {
            $this->log-error("The specified certificate file: {$cdcCertificateFile} does not exist.");

            throw new InvalidArgumentException("The specified certificate file: {$cdcCertificateFile} does not exist.");
        }

        $pkcs12 = file_get_contents($pkcs12File);
        $certificates = array();

        if (!openssl_pkcs12_read($pkcs12, $certificates, $pkcs12Password)) {
            $this->log->error("Unable to read PCKS12 file {$pkcs12File}");

            throw new Exception("Unable to read PCKS12 file {$pkcs12File}");
        }

        $this->log->info("PCKS12 file: '{$pkcs12File}' loaded successfully!");

        if (!isset($certificates['pkey'])) {
            $this->log->error("Unable to load private key from PCKS12 file {$pkcs12File}");

            throw new Exception("Unable to load private key from PCKS12 file {$pkcs12File}");
        }

        $this->privateKey = openssl_pkey_get_private($certificates['pkey']);

        $this->log->info("Private key loaded successfully!");

        $publicCertificate = file_get_contents($cdcCertificateFile);

        if ($publicCertificate === null || empty($publicCertificate)) {
            $this->log->error("The specified public certificate {$publicCertificate} is empty.");

            throw new InvalidArgumentException("The specified public certificate {$publicCertificate} is empty.");
        }

        $this->publicKey = openssl_pkey_get_public($publicCertificate);

        $this->log->info("Public certificate: '{$cdcCertificateFile}' loaded successfully!");
    }

    /**
     * Generate a digital signature from the data passed as argument using the provided cryptographic keys
     * during the construction of this object.
     * 
     * NOTE: Algorithm used for signature generation: SHA256withECDSA - secp384r
     * 
     * @param string $plainText The data that will be signed.
     * 
     * @return string If the signature process is successful the generated signature encoded as hexadecimal is returned.
     * 
     * @throws InvalidArgumentException If the provided $plainText is emtpy or null.
     * @throws Exception                If an error occurs during the signature process.
     */
    public function generateDigitalSignature($plainText): string
    {
        
        $this->log->info("Starting signature process ...");

        if ($plainText === null || empty($plainText)) {
            $this->log->info("The plain text provided for the signature is emtpy.");

            throw new InvalidArgumentException("The plain text provided for the signature is emtpy.");
        }

        if ($this->privateKey === null || $this->publicKey === null) {
            $this->log->info("Unable to sign, the private key or the public certificate are empty.");

            throw new Exception("Unable to sign, the private key or the public certificate are empty.");
        }

        $signature = null;

        if (!openssl_sign($plainText, $signature, $this->privateKey, OPENSSL_ALGO_SHA256)) {
            $this->log->error("Failed to sign the provided plain text, an unexpected error occurs.");

            throw new Exception("Failed to sign the provided plain text, an unexpected error occurs.");
        }

        $hexSignature = bin2hex($signature);

        $this->log->info("Signature process finished successfully!");
        $this->log->info("Generated signature: {$hexSignature}");

        return $hexSignature;
    }

    /**
     * Validate that the provided signature is valid and correspond with the provided plain text data.
     * 
     * @param string $plainText The data that was signed.
     * @param string $signature The signature that will be verified against the provided plain text.
     * 
     * @return bool Return true if the signature is valid otherwise false.
     * 
     * @throws InvalidArgumentException If the provided arguments are emtpy or null.
     * @throws Exception                If an error occurs during the signature validation process.
     */
    public function isDigitalSigantureValid($plainText, $signature): bool
    {
        
        $this->log->info("Starting signature verification process ...");

        if ($plainText === null || empty($plainText)) {
            $this->log->error("The provided plain text for verification is emtpy.");
            throw new InvalidArgumentException("The provided plain text for verification is emtpy.");
        }

        if ($signature === null || empty($signature)) {
            $this->log->error("The provided plain text for verification is emtpy.");
            throw new InvalidArgumentException("The provided signature for verification is emtpy.");
        }

        if ($this->publicKey === null) {
            $this->log->error("Unable to verify signature, the public certificate is not set.");
            throw new Exception("Unable to verify signature, the public certificate is not set.");
        }

        $this->log->info("Verifying the digital signature ...");

        $binarySignature = hex2bin($signature);

        $result = openssl_verify($plainText, $binarySignature, $this->publicKey, OPENSSL_ALGO_SHA256);

        if ($result === 1) {
            $this->log->info("The digital signature is valid!");
            return true;
        }

        $this->log->warning("The digital signature is invalid!");
        return false;
    }
}
