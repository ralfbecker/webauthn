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
use Webauthn\AttestationStatement\AttestationObjectLoader;
//use Webauthn\AttestationStatement\AndroidSafetyNetAttestationStatementSupport;
use Webauthn\AttestationStatement\AndroidKeyAttestationStatementSupport;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\FidoU2FAttestationStatementSupport;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AttestationStatement\TPMAttestationStatementSupport;
use Webauthn\AuthenticationExtensions\ExtensionOutputCheckerHandler;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\PublicKeyCredentialLoader;
use Webauthn\TokenBinding\TokenBindingNotSupportedHandler;
use EGroupware\WebAuthn\PubkeyCredentialsRepo;

// Retrieve the PublicKeyCredentialCreationOptions object created earlier
session_start();
$publicKeyCredentialCreationOptions = unserialize($_SESSION['publicKeyCredentialCreationOptions']);
error_log("publicKeyCredentialCreationOptions from session=".json_encode($publicKeyCredentialCreationOptions));

// Retrieve de data sent by the device
$data = base64_decode($_GET['data']);
error_log("data from request=$data");

// Cose Algorithm Manager
$coseAlgorithmManager = new Manager();
$coseAlgorithmManager->add(new ECDSA\ES256());
$coseAlgorithmManager->add(new ECDSA\ES512());
$coseAlgorithmManager->add(new EdDSA\EdDSA());
$coseAlgorithmManager->add(new RSA\RS1());
$coseAlgorithmManager->add(new RSA\RS256());
$coseAlgorithmManager->add(new RSA\RS512());

// Create a CBOR Decoder object
$otherObjectManager = new OtherObjectManager();
$tagObjectManager = new TagObjectManager();
$decoder = new Decoder($tagObjectManager, $otherObjectManager);

// The token binding handler
$tokenBindnigHandler = new TokenBindingNotSupportedHandler();

// Attestation Statement Support Manager
$attestationStatementSupportManager = new AttestationStatementSupportManager();
$attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
$attestationStatementSupportManager->add(new FidoU2FAttestationStatementSupport($decoder));
//$attestationStatementSupportManager->add(new AndroidSafetyNetAttestationStatementSupport($httpClient, 'GOOGLE_SAFETYNET_API_KEY'));
$attestationStatementSupportManager->add(new AndroidKeyAttestationStatementSupport($decoder));
$attestationStatementSupportManager->add(new TPMAttestationStatementSupport());
$attestationStatementSupportManager->add(new PackedAttestationStatementSupport($decoder, $coseAlgorithmManager));

// Attestation Object Loader
$attestationObjectLoader = new AttestationObjectLoader($attestationStatementSupportManager, $decoder);

// Public Key Credential Loader
$publicKeyCredentialLoader = new PublicKeyCredentialLoader($attestationObjectLoader, $decoder);

// Credential Repository
$publicKeyCredentialSourceRepository = new PubkeyCredentialsRepo();

// Extension Output Checker Handler
$extensionOutputCheckerHandler = new ExtensionOutputCheckerHandler();

// Authenticator Attestation Response Validator
$authenticatorAttestationResponseValidator = new AuthenticatorAttestationResponseValidator(
    $attestationStatementSupportManager,
    $publicKeyCredentialSourceRepository,
    $tokenBindnigHandler,
    $extensionOutputCheckerHandler
);

try {
    // We init the PSR7 Request object
    $symfonyRequest = Request::createFromGlobals();
    $psr7Request = (new DiactorosFactory())->createRequest($symfonyRequest);

    // Load the data
    $publicKeyCredential = $publicKeyCredentialLoader->load($data);
    $response = $publicKeyCredential->getResponse();

    // Check if the response is an Authenticator Attestation Response
    if (!$response instanceof AuthenticatorAttestationResponse) {
        throw new \RuntimeException('Not an authenticator attestation response');
    }

    // Check the response against the request
    $authenticatorAttestationResponseValidator->check($response, $publicKeyCredentialCreationOptions, $psr7Request);
} catch (\Throwable $exception) {
    ?>
    <html>
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

// Everything is OK here.

// You can get the Public Key Credential Source. This object should be persisted using the Public Key Credential Source repository
$publicKeyCredentialSource = \Webauthn\PublicKeyCredentialSource::createFromPublicKeyCredential(
    $publicKeyCredential,
    $publicKeyCredentialCreationOptions->getUser()->getId()
);
$publicKeyCredentialSourceRepository->saveCredentialSource($publicKeyCredentialSource);


//You can also get the PublicKeyCredentialDescriptor.
$publicKeyCredentialDescriptor = $publicKeyCredential->getPublicKeyCredentialDescriptor();
error_log('$publicKeyCredential->getPublicKeyCredentialDescriptor()='.json_encode($publicKeyCredentialDescriptor));

// Normally this condition should be true. Just make sure you received the credential data
$attestedCredentialData = null;
if ($response->getAttestationObject()->getAuthData()->hasAttestedCredentialData()) {
    $attestedCredentialData = $response->getAttestationObject()->getAuthData()->getAttestedCredentialData();
}

//You could also access to the following information.
$response->getAttestationObject()->getAuthData()->getSignCount(); // Current counter
$response->getAttestationObject()->getAuthData()->isUserVerified(); // Indicates if the user was verified
$response->getAttestationObject()->getAuthData()->isUserPresent(); // Indicates if the user was present
$response->getAttestationObject()->getAuthData()->hasExtensions(); // Extensions are available
$response->getAttestationObject()->getAuthData()->getExtensions(); // The extensions
$response->getAttestationObject()->getAuthData()->getReservedForFutureUse1(); //Not used at the moment
$response->getAttestationObject()->getAuthData()->getReservedForFutureUse2(); //Not used at the moment

header('Content-Type: text/html');
?>
    <html>
    <head>
        <title>Device registration</title>
    </head>
    <body>
    <h1>OK registered</h1>
    <p><a href="login.php">Go to login now</a></p>
    </body>
</html>
