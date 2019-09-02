<?php

declare(strict_types=1);

include __DIR__.'/../vendor/autoload.php';

use Zend\Diactoros\ServerRequestFactory;
use EGroupware\WebAuthn\PublickeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Server;

// Retrieve the Options passed to the device
session_start();
if (!isset($_SESSION['publicKeyCredentialRequestOptions']) || !is_string($_SESSION['publicKeyCredentialRequestOptions'])) {
    header('location: login.php', true, 307);
    exit();
}
$publicKeyCredentialRequestOptions =  PublicKeyCredentialRequestOptions::createFromString($_SESSION['publicKeyCredentialRequestOptions']);
error_log("PublicKeyCredentialRequestOptions from session=".json_encode($publicKeyCredentialRequestOptions));

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

// User Entity
$userEntity = new PublicKeyCredentialUserEntity(
    '@cypher-Angel-3000',                   //Name
    '123e4567-e89b-12d3-a456-426655440000', //ID
    'Mighty Mike',                          //Display name
    null                                    //Icon
);

// Retrieve de data sent by the device
$data = base64_decode($_GET['data']);
error_log("data from request=$data");


try {
    // We init the PSR7 Request object
	$psr7Request = ServerRequestFactory::fromGlobals();
    $publicKeyCredentialSource = $server->loadAndCheckAssertionResponse(
        $data,
        $publicKeyCredentialRequestOptions,
        $userEntity,
        $psr7Request
    );
    ?>
        <html>
        <head>
            <title>Login</title>
        </head>
        <body>
            <h1>OK logged in!</h1>
        </body>
    </html>
    <?php
} catch (Throwable $throwable) {
    ?>
    <html>
    <head>
        <title>Login</title>
    </head>
    <body>
        <h1>Something went wrong!</h1>
        <p>The error message is: <?= $throwable->getMessage(); ?></p>
        <pre><?= $throwable->getTraceAsString(); ?></pre>
        <p><a href="login.php">Go back to login page</a></p>
    </body>
    </html>
    <?php
}