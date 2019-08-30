<?php

declare(strict_types=1);

include __DIR__.'/vendor/autoload.php';

use CBOR\Decoder;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA;
use Cose\Algorithm\Signature\EdDSA;
use Cose\Algorithm\Signature\RSA;
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
use Symfony\Component\HttpFoundation\Request;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AttestationStatement\AttestationObjectLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;
use EGroupware\WebAuthn\PubkeyCredentialsRepo;


// Retrieve the Options passed to the device
session_start();
$publicKeyCredentialRequestOptions = unserialize($_SESSION['publicKeyCredentialRequestOptions']);
error_log("publicKeyCredentialRequest from session=".json_encode($publicKeyCredentialRequestOptions));

// Cose Algorithm Manager
$coseAlgorithmManager = new Manager();
$coseAlgorithmManager->add(new ECDSA\ES256());
$coseAlgorithmManager->add(new ECDSA\ES512());
$coseAlgorithmManager->add(new EdDSA\EdDSA());
$coseAlgorithmManager->add(new RSA\RS1());
$coseAlgorithmManager->add(new RSA\RS256());
$coseAlgorithmManager->add(new RSA\RS512());

// Retrieve de data sent by the device

// Retrieve de data sent by the device
$data = base64_decode($_GET['data']);
error_log("data from request=$data");

// Create a CBOR Decoder object
$otherObjectManager = new OtherObjectManager();
$tagObjectManager = new TagObjectManager();
$decoder = new Decoder($tagObjectManager, $otherObjectManager);

// Attestation Statement Support Manager
$attestationStatementSupportManager = new AttestationStatementSupportManager();
$attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
$attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport($decoder));
$attestationStatementSupportManager->add(new PackedAttestationStatementSupport($decoder, $coseAlgorithmManager));

// Attestation Object Loader
$attestationObjectLoader = new AttestationObjectLoader($attestationStatementSupportManager, $decoder);

// Public Key Credential Loader
$publicKeyCredentialLoader = new PublicKeyCredentialLoader($attestationObjectLoader, $decoder);

// Public Key Credential Source Repository
$publicKeyCredentialSourceRepository = new PubkeyCredentialsRepo();

// The token binding handler
$tokenBindnigHandler = new TokenBindingNotSupportedHandler();

// Extension Output Checker Handler
$extensionOutputCheckerHandler = new ExtensionOutputCheckerHandler();

// Authenticator Assertion Response Validator
$authenticatorAssertionResponseValidator = new AuthenticatorAssertionResponseValidator(
  $publicKeyCredentialSourceRepository,
  $decoder,
  $tokenBindnigHandler,
  $extensionOutputCheckerHandler,
  $coseAlgorithmManager
);

try {
    // We init the PSR7 Request object
    $symfonyRequest = Request::createFromGlobals();
    $psr7Request = (new DiactorosFactory())->createRequest($symfonyRequest);

    // Load the data
    $publicKeyCredential = $publicKeyCredentialLoader->load($data);
    $response = $publicKeyCredential->getResponse();

    // Check if the response is an Authenticator Assertion Response
    if (!$response instanceof AuthenticatorAssertionResponse) {
        throw new \RuntimeException('Not an authenticator assertion response');
    }

	// according to https://www.w3.org/TR/webauthn/#conforming-authenticators-u2f u2f token return no userHandle
	// but the check below requires it :(
	if (null === $response->getUserHandle() &&
		($pubkey = $publicKeyCredentialSourceRepository->findOneByCredentialId($publicKeyCredential->getRawId())) &&
		$pubkey->getUserHandle())
	{
		error_log('Response has no userHandle, using stored one from public key');
		$response = new AuthenticatorAssertionResponse(
			$response->getClientDataJSON(),
			$response->getAuthenticatorData(),
			$response->getSignature(),
			base64_encode($pubkey->getUserHandle()));
	}

    // Check the response against the attestation request
    $authenticatorAssertionResponseValidator->check(
        $publicKeyCredential->getRawId(),
        $response,
        $publicKeyCredentialRequestOptions,
        $psr7Request,
        null // User handle: null or the user ID if you know it
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
} catch (\Throwable $throwable) {
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