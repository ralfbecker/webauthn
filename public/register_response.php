<?php

declare(strict_types=1);

include __DIR__.'/../vendor/autoload.php';

use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
use Symfony\Component\HttpFoundation\Request;
use EGroupware\WebAuthn\PublickeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\Server;

// Retrieve the PublicKeyCredentialCreationOptions object created earlier
session_start();
if (!isset($_SESSION['publicKeyCredentialCreationOptions']) || !is_string($_SESSION['publicKeyCredentialCreationOptions'])) {
    header('location: register.php', true, 307);
    exit();
}

$publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::createFromString($_SESSION['publicKeyCredentialCreationOptions']);
error_log("publicKeyCredentialCreationOptions from session=".json_encode($publicKeyCredentialCreationOptions));

// Retrieve de data sent by the device
$data = base64_decode($_GET['data']);
error_log("data from request=$data");

// Credential Repository
$publicKeyCredentialSourceRepository = new PublickeyCredentialSourceRepository();

// RP Entity
$rpEntity = new PublicKeyCredentialRpEntity(
    'My Super Secured Application', //Name
    preg_replace('/:.*$/', '', $_SERVER['HTTP_HOST']),              //ID
    null                            //Icon
);

// New Server class introduced in v2.1
$server = new Server(
    $rpEntity,
    $publicKeyCredentialSourceRepository,
    null
);

try {
    // We init the PSR7 Request object
    $symfonyRequest = Request::createFromGlobals();
    $psr7Request = (new DiactorosFactory())->createRequest($symfonyRequest);

    // Check the response against the request
    $publicKeyCredentialSource = $server->loadAndCheckAttestationResponse($data, $publicKeyCredentialCreationOptions, $psr7Request);

    // Everything is OK here.

    // You can get the Public Key Credential Source. This object should be persisted using the Public Key Credential Source repository
    $publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);


    //You can also get the PublicKeyCredentialDescriptor.
    $publicKeyCredentialDescriptor = $publicKeyCredentialSource->getPublicKeyCredentialDescriptor();
    error_log('$publicKeyCredential->getPublicKeyCredentialDescriptor()='.json_encode($publicKeyCredentialDescriptor));

    header('Content-Type: text/html');
    ?>
    <html lang="en">
    <head>
        <title>Device registration</title>
    </head>
    <body>
    <h1>OK registered</h1>
    <p><a href="login.php">Go to login now</a></p>
    </body>
    </html>

    <?php
    } catch (\Throwable $exception) {
    ?>
    <html lang="en">
    <head>
        <title>Device registration</title>
    </head>
    <body>
    <h1>The device cannot be registered</h1>
    <p>The error message is: <?= $exception->getMessage(); ?></p>
    <pre><?= $exception->getTraceAsString(); ?></pre>
    <p><a href="register.php">Go back to registration page</a></p>
    </body>
    <?php
    exit();
}
