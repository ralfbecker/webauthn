<?php

declare(strict_types=1);

include __DIR__.'/../vendor/autoload.php';

use EGroupware\WebAuthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\Server;

// Credential Repository
$publicKeyCredentialSourceRepository = new PublicKeyCredentialSourceRepository();

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

$repo = new PublicKeyCredentialSourceRepository();
$registeredPublicKeyCredentialSources = $repo->findAllForUserEntity($userEntity);
$registeredPublicKeyCredentialDescriptors = array_map(static function(PublicKeyCredentialSource $item) {
    return $item->getPublicKeyCredentialDescriptor();
}, $registeredPublicKeyCredentialSources);

// Public Key Credential Request Options
$publicKeyCredentialRequestOptions = $server->generatePublicKeyCredentialRequestOptions(
    PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_PREFERRED,
    $registeredPublicKeyCredentialDescriptors
);
$encodedOptions = json_encode($publicKeyCredentialRequestOptions, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

session_start();
$_SESSION['publicKeyCredentialRequestOptions'] = $encodedOptions;

header('Content-Type: text/html');
?>
<html>
    <head>
        <title>Login</title>
    </head>
    <body>
    <script>
        const publicKey = <?php echo $encodedOptions; ?>;

        function arrayToBase64String(a) {
            return btoa(String.fromCharCode(...a));
        }

        function base64url2base64(input) {
            // Replace non-url compatible chars with base64 standard chars
            input = input
                .replace(/-/g, '+')
                .replace(/_/g, '/');

            // Pad out with standard base64 required padding characters
            const pad = input.length % 4;
            if(pad) {
                if(pad === 1) {
                    throw new Error('InvalidLengthError: Input base64url string is the wrong length to determine padding');
                }
                input += new Array(5-pad).join('=');
            }

            return input;
        }

        publicKey.challenge = Uint8Array.from(window.atob(base64url2base64(publicKey.challenge)), function(c){return c.charCodeAt(0);});
        if (publicKey.allowCredentials) {
            publicKey.allowCredentials = publicKey.allowCredentials.map(function(data) {
                data.id = Uint8Array.from(window.atob(base64url2base64(data.id)), function(c){return c.charCodeAt(0);});
                return data;
            });
        }

        navigator.credentials.get({ 'publicKey': publicKey })
            .then(function(data){
                const publicKeyCredential = {
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
            })
            .catch(function(error){
                alert('Open your browser console!');
                console.log('FAIL', error);
            });
    </script>
    <h1>Login</h1>
    <p>Please push the blue button!</p>
    </body>
</html>