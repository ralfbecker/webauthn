<?php

declare(strict_types=1);

include __DIR__.'/vendor/autoload.php';

use Webauthn\AuthenticationExtensions\AuthenticationExtension;
use Webauthn\AuthenticationExtensions\AuthenticationExtensionsClientInputs;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use EGroupware\WebAuthn\PubkeyCredentialsRepo;

// Extensions
$extensions = new AuthenticationExtensionsClientInputs();
$extensions->add(new AuthenticationExtension('loc', true));

// List of registered PublicKeyCredentialDescriptor classes associated to the user
// User Entity
$userEntity = new PublicKeyCredentialUserEntity(
    '@cypher-Angel-3000',                   //Name
    '123e4567-e89b-12d3-a456-426655440000', //ID
    'Mighty Mike',                          //Display name
    null                                    //Icon
);
$repo = new PubkeyCredentialsRepo();
$registeredPublicKeyCredentialDescriptors = $repo->findAllForUserEntity($userEntity);

// Public Key Credential Request Options
$publicKeyCredentialRequestOptions = new PublicKeyCredentialRequestOptions(
    random_bytes(32),                                                           // Challenge
    60000,                                                                      // Timeout
    preg_replace('/:.*$/', '', $_SERVER['HTTP_HOST']),                          // Relying Party ID
    $registeredPublicKeyCredentialDescriptors,                                  // Registered PublicKeyCredentialDescriptor classes
    PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED, // User verification requirement
    $extensions
);

session_start();
$_SESSION['publicKeyCredentialRequestOptions'] = serialize($publicKeyCredentialRequestOptions);

header('Content-Type: text/html');
?>
<html>
    <head>
        <title>Login</title>
    </head>
    <body>
    <script>
        let publicKey = <?php echo json_encode($publicKeyCredentialRequestOptions, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); ?>;

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
        publicKey.allowCredentials = publicKey.allowCredentials.map(function(data) {
            return {
                ...data,
                'id': Uint8Array.from(atob(base64url2base64(data.publicKeyCredentialId)), c=>c.charCodeAt(0))
            };
        });

        navigator.credentials.get({publicKey})
            .then(data => {
                let publicKeyCredential = {
                    id: data.id,
                    type: data.type,
                    rawId: arrayToBase64String(new Uint8Array(data.rawId)),
                    response: {
                        authenticatorData: arrayToBase64String(new Uint8Array(data.response.authenticatorData)),
                        clientDataJSON: arrayToBase64String(new Uint8Array(data.response.clientDataJSON)),
                        signature: arrayToBase64String(new Uint8Array(data.response.signature)),
                        userHandle: data.response.userHandle ? arrayToBase64String(new Uint8Array(data.response.userHandle)) : null
                    }
                };
                window.location = window.location.pathname.replace('login.php', 'login_response.php')+
					'?data='+btoa(JSON.stringify(publicKeyCredential));
            }, error => {
                console.log(error); // Example: timeout, interaction refused...
            });
    </script>
    <h1>Login</h1>
    <p>Please push the blue button!</p>
    </body>
</html>