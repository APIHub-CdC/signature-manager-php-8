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

use \GuzzleHttp\Middleware;
use \GuzzleHttp\Psr7\Stream;
use \Psr\Http\Message\RequestInterface;
use \Psr\Http\Message\ResponseInterface;

use \Signer\Manager\Interceptor\SignatureService;
use \Signer\Manager\Interceptor\MyLogger;

/**
 * HTTP Request/Response interceptor component to generate and validate the digital signature 'x-siganture'
 * for the 'Círculo de Crédito' APIs.
 * 
 * IMPORTANT: Openssl MUST be installed on your system.
 * 
 * @author Gamaliel Lobato
 * @author Ricardo Rubio
 * 
 * @copyright 2020-2023 Círculo de Crédito
 */
class MiddlewareEvents
{
    /**
     * Constructor.
     * 
     * @param SignatureService $signatureService Object service that generate and validate digital signatures.
     */
    function __construct(\Signer\Manager\Interceptor\SignatureService $signatureService)
    {
        $this->signatureService = $signatureService;
        $this->log = new MyLogger('MiddlewareEvents');
    }
    
    /**
     * Generate the HTTP Request Header 'x-signature" digital signature.
     * 
     * @param string $headerName    The name of the HTTP that will store the generated digital signature.
     *                              Unless otherwise specified this always MUST be 'x-signature'
     */
    function add_signature_header($headerName)
    {
        return middleware::mapRequest(function (RequestInterface $request) use ($headerName) {

            $signature = null;

            try {
                if ($request->getMethod() == "POST") {
                    $this->log->info("Beginning signature of HTTP POST Body ...");
                    
                    $payload = $request->getBody()->getContents();
                    $request->getBody()->rewind();

                    $signature = $this->signatureService->generateDigitalSignature($payload);

                } else if ($request->getMethod() == "GET") {
                    $this->log->info("Beginning signature of HTTP GET URL ...");
                    $signature = $this->signatureService->getSignatureFromPrivateKey($request->getUri());

                } else {
                    $this->log->warning("The HTTP method {$request->getMethod()} is not supported for signing!");
                }

            } catch (Exception $exception) {
                $this->log->error(
                    "Failed to sign HTTP Request. Cause: {$exception->getCode()} {$exception->getMessage()}");
            }
            
            return $request->withHeader($headerName, $signature);
        });
    }

    /**
     * Verify that the HTTP Response x-signature value is a valid digital signature.
     * 
     * @param string $headerName    The name of the HTTP Header that contains the signature that will be validated.
     *                              Unless otherwise specified this always MUST be 'x-signature'
     */
    function verify_signature_header($headerName)
    {
        return \GuzzleHttp\Middleware::mapResponse(function (ResponseInterface $response) use ($headerName) {
            
            try {
                $this->log->info("Beginning verification of HTTP Response Body ...");
                $this->log->info("Response HTTP status code: {$response->getStatusCode()}");
                
                $body = $response->getBody()->getContents();
                $body = strlen($body) > 254 ? $body.' ...truncated' : $body;
                
                $response->getBody()->rewind();    
               
                $this->log->info("HTTP Response Body to verify: {$body}");
                
                if (!isset($response->getHeaders()[$headerName][0])) {
                    $this->log->error(
                        "Failed to verify HTTP Header Response x-signature, x-signature Header not found.");

                    return $response;
                }

                $signature = $response->getHeaders()[$headerName][0];                   
                
                if ($this->signatureService->isDigitalSigantureValid($body, $signature)) {
                    $this->log->info("The HTTP Header Response x-signature is valid!");

                } else {
                    $this->log->warning("The HTTP Header Response x-signature is invalid!");
                }

            } catch (Exception $exception) {
                $this->log->error(
                    "Failed to verify HTTP Response Header x-signature. Cause: "
                    ."{$exception->getCode()} {$exception->getMessage()}"
                );
            }

            return $response;
        });
    }
}
