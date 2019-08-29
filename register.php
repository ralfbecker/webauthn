<?php

declare(strict_types=1);

include __DIR__.'/vendor/autoload.php';

use Cose\Algorithms;
use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

// RP Entity
$rpEntity = new PublicKeyCredentialRpEntity(
    'My Super Secured Application', //Name
    preg_replace('/:.*$/', '', $_SERVER['HTTP_HOST']),              //ID
    null                            //Icon
);

// User Entity
$userEntity = new PublicKeyCredentialUserEntity(
    '@cypher-Angel-3000',                   //Name
    '123e4567-e89b-12d3-a456-426655440000', //ID
    'Mighty Mike',                          //Display name
    null                                    //Icon
);

// Challenge
$challenge = random_bytes(32);

// Public Key Credential Parameters
$publicKeyCredentialParametersList = [
    new PublicKeyCredentialParameters('public-key', Algorithms::COSE_ALGORITHM_ES256),
];

// Timeout
$timeout = 20000;

// Devices to exclude
$excludedPublicKeyDescriptors = [
    new PublicKeyCredentialDescriptor(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, 'ABCDEFGH'),
];

// Authenticator Selection Criteria (we used default values)
$authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria();

// Extensions
$extensions = new AuthenticationExtensionsClientInputs();
$extensions->add(new AuthenticationExtension('loc', true));

$publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(
    $rpEntity,
    $userEntity,
    $challenge,
    $publicKeyCredentialParametersList,
    $timeout,
    $excludedPublicKeyDescriptors,
    $authenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
    $extensions
);

session_start();
$_SESSION['publicKeyCredentialCreationOptions'] = serialize($publicKeyCredentialCreationOptions);
?>

<html>
    <head>
        <meta charset="UTF-8" />
        <title>Request</title>
    </head>
    <body>
    <script>
        let publicKey = <?php echo json_encode($publicKeyCredentialCreationOptions, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); ?>;

        function arrayToBase64String(a) {
            return btoa(String.fromCharCode(...a));
        }

		function base64url2base64(input) {
			// Replace non-url compatible chars with base64 standard chars
			input = input
				.replace(/-/g, '+')
				.replace(/_/g, '/');

			// Pad out with standard base64 required padding characters
			var pad = input.length % 4;
			if(pad) {
			  if(pad === 1) {
				throw new Error('InvalidLengthError: Input base64url string is the wrong length to determine padding');
			  }
			  input += new Array(5-pad).join('=');
			}

			return input;
		}

        publicKey.challenge = Uint8Array.from(window.atob(base64url2base64(publicKey.challenge)), c=>c.charCodeAt(0));
        publicKey.user.id = Uint8Array.from(window.atob(publicKey.user.id), c=>c.charCodeAt(0));
        if (publicKey.excludeCredentials) {
            publicKey.excludeCredentials = publicKey.excludeCredentials.map(function(data) {
                return {
                    ...data,
                    'id': Uint8Array.from(window.atob(data.id), c=>c.charCodeAt(0))
                };
            });
        }

        navigator.credentials.create({publicKey})
            .then(function (data) {
                let publicKeyCredential = {

                    id: data.id,
                    type: data.type,
                    rawId: arrayToBase64String(new Uint8Array(data.rawId)),
                    response: {
                        clientDataJSON: arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
                        attestationObject: arrayToBase64String(new Uint8Array(data.response.attestationObject))
                    }
                };
                window.location = '/egroupware/webauthn/registration_response.php?data='+btoa(JSON.stringify(publicKeyCredential));
            }, function (error) {
                console.log(error); // Example: timeout, interaction refused...
            });
    </script>
    </body>
</html>