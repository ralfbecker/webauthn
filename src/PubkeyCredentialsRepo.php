<?php
/**
 * EGroupware WebAuthn
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\WebAuthn;

//use EGroupware\Api;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

class PubkeyCredentialsRepo implements PublicKeyCredentialSourceRepository
{
	protected $path = '/tmp/pubkey-repo.json';

    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
	{
		$data = $this->read();
		error_log(__METHOD__."('$publicKeyCredentialId') returning ".json_encode($data[base64_encode($publicKeyCredentialId)]));
		if (isset($data[base64_encode($publicKeyCredentialId)]))
		{
			return PublicKeyCredentialSource::createFromArray($data[base64_encode($publicKeyCredentialId)]);
		}
		return null;
	}

    /**
     * @return PublicKeyCredentialSource[]
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
	{
		$sources = [];
		foreach($this->read() as $data)
		{
			$source = PublicKeyCredentialSource::createFromArray($data);
			if ($source->getUserHandle() === $publicKeyCredentialUserEntity->getId())
			{
				$sources[] = $source;
			}
		}
		error_log(__METHOD__."(".json_encode($publicKeyCredentialUserEntity).") returning ".json_encode($sources));
		return $sources;
	}

    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
	{
		error_log(__METHOD__."(".json_encode($publicKeyCredentialSource).")");
		$data = $this->read();
		$data[base64_encode($publicKeyCredentialSource->getPublicKeyCredentialId())] = $publicKeyCredentialSource;
		$this->write($data);
	}

	protected function read()
	{
		if (file_exists($this->path))
		{
			return json_decode(file_get_contents($this->path), true);
		}
		return [];
	}

	protected function write(array $data)
	{
		if (!file_exists($this->path))
		{
			@mkdir(dirname($this->path), 0700, true);
		}
		file_put_contents($this->path, json_encode($data), LOCK_EX);
	}
}
